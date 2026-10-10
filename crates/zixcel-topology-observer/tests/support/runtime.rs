use std::{
    fs,
    io::Write,
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use crowsi_local_control_bridge::{
    BridgeError, BridgeTrust, CurrentStatusBinding, DurableSecurityStore, IdentityStatusTrust,
    LocalControlBridge, LocalControlServer, PrivateUnixListener, SystemTrustedClock,
};
use tempfile::TempDir;
use zixcel_topology_observer::{
    ObservationReceiptV1, ObserverError, ResponseReplayStore, TopologyObservationClient,
    TopologyObservationHandler, ZixcelResponseTrust, canonical_operation, sha256_digest,
};

use super::{AuthorizationOptions, Tamper, WORKLOAD, material::Material, zixcel::ServerFixture};

type Server =
    LocalControlServer<SystemTrustedClock, TopologyObservationHandler<SystemTrustedClock>>;
static INTEGRATION_LOCK: Mutex<()> = Mutex::new(());

pub struct RuntimeFixture {
    _serial: MutexGuard<'static, ()>,
    _root: TempDir,
    pub material: Material,
    server: Server,
    zixcel: Option<ServerFixture>,
}

pub struct Exchange {
    pub client: Result<ObservationReceiptV1, ObserverError>,
    pub server: Result<(), BridgeError>,
}
impl RuntimeFixture {
    pub fn new(options: &AuthorizationOptions) -> Self {
        Self::with_executable(options, &executable_digest())
    }

    pub fn with_executable(options: &AuthorizationOptions, digest: &str) -> Self {
        let serial = INTEGRATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = private_root();
        let zixcel = ServerFixture::new(root.path());
        let material = Material::new(&zixcel.url, options);
        let trust = BridgeTrust::new(
            material.pa_public_key,
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
            WORKLOAD,
            digest,
            identity_status_trust(),
        )
        .expect("bridge trust");
        let mut bridge = LocalControlBridge::new(
            trust,
            DurableSecurityStore::open(root.path().join("bridge.sqlite3"), 20)
                .expect("bridge state"),
            SystemTrustedClock::new().expect("bridge clock"),
        );
        let status = &material.status;
        let binding = CurrentStatusBinding::new(
            &status.pairwise_subject,
            &status.service_id,
            &status.device_id,
            &status.device_proof_key_ref,
            &status.session_ref,
        )
        .expect("status binding");
        bridge
            .apply_current_device_status(
                &serde_json::to_vec(status).expect("status JSON"),
                &binding,
            )
            .expect("status anchor");
        let response_trust =
            ZixcelResponseTrust::load(&root.path().join("zixcel-response-trust.json"), &zixcel.url)
                .expect("response trust");
        let handler = TopologyObservationHandler::new(
            response_trust,
            ResponseReplayStore::open(&root.path().join("observer.sqlite3"))
                .expect("observer state"),
            SystemTrustedClock::new().expect("observer clock"),
        );
        let listener =
            PrivateUnixListener::bind(root.path().join("observer.sock")).expect("private socket");
        let server = LocalControlServer::new(listener, bridge, handler, Duration::from_secs(15));
        Self {
            _serial: serial,
            _root: root,
            material,
            server,
            zixcel: Some(zixcel),
        }
    }

    pub fn exchange(&mut self, response: Option<Tamper>) -> Exchange {
        let response_thread =
            response.map(|tamper| self.zixcel.take().expect("one fake response").start(tamper));
        let socket = self.server.socket_path().to_owned();
        let client = TopologyObservationClient::new(Duration::from_secs(15)).expect("client");
        let (client_result, server_result) = std::thread::scope(|scope| {
            let server = scope.spawn(|| self.server.serve_one());
            let client_result = client.observe(&socket, &self.material.bundle);
            (client_result, server.join().expect("observer thread"))
        });
        if let Some(thread) = response_thread {
            thread.join().expect("Zixcel thread");
        }
        Exchange {
            client: client_result,
            server: server_result,
        }
    }

    pub fn reject_missing_authorization(&mut self) -> Result<(), BridgeError> {
        let socket = self.server.socket_path().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| self.server.serve_one());
            let mut stream = UnixStream::connect(socket).expect("private IPC");
            stream.write_all(&0_u32.to_be_bytes()).expect("empty frame");
            server.join().expect("observer thread")
        })
    }

    pub fn reject_trailing_operation(&mut self) -> Result<(), BridgeError> {
        let socket = self.server.socket_path().to_owned();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| self.server.serve_one());
            let mut stream = UnixStream::connect(socket).expect("private IPC");
            write_frame(
                &mut stream,
                &serde_json::to_vec(&self.material.bundle.authorization)
                    .expect("authorization frame"),
            );
            write_frame(
                &mut stream,
                &canonical_operation(&self.material.bundle.operation).expect("operation frame"),
            );
            stream.write_all(b"x").expect("trailing byte");
            stream.shutdown(Shutdown::Write).expect("half close");
            server.join().expect("observer thread")
        })
    }
}

include!("runtime_helpers.rs");
