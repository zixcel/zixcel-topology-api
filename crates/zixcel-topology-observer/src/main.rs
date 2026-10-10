use std::{path::Path, process::ExitCode, time::Duration};

use zixcel_topology_observer::{
    ObservationBundleV1, TopologyObservationClient, load_server, read_owner_only_json,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!(
                "{{\"schema\":\"crowsi://topology-observer/cli-error/v1\",\
                 \"error_code\":{}}}",
                serde_json::to_string(code).unwrap_or_else(|_| "\"observer-failed\"".into())
            );
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), &'static str> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, config] if command == "serve-one" => {
            let mut server =
                load_server(Path::new(config)).map_err(|_| "observer-deployment-invalid")?;
            server
                .serve_one()
                .map_err(|_| "topology-observation-rejected")
        }
        [command, socket, bundle] if command == "observe" => {
            let bundle: ObservationBundleV1 = read_owner_only_json(Path::new(bundle), 65_536)
                .map_err(|_| "observation-bundle-invalid")?;
            let receipt = TopologyObservationClient::new(Duration::from_secs(5))
                .and_then(|client| client.observe(Path::new(socket), &bundle))
                .map_err(|_| "topology-observation-rejected")?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|_| "receipt-serialization-failed")?
            );
            Ok(())
        }
        [command] if command == "sample-readiness" => {
            println!(
                "{{\"schema\":\"crowsi://topology-observer/readiness/v1\",\
                 \"state\":\"unavailable\",\"external_network\":false,\
                 \"reason_codes\":[\"pa-per-use-authorization-not-provisioned\",\
                 \"dedicated-os-identity-not-provisioned\",\
                 \"root-provisioned-socket-directory-not-attested\",\
                 \"hardware-trusted-clock-not-provisioned\"]}}"
            );
            Ok(())
        }
        _ => Err("usage-required"),
    }
}
