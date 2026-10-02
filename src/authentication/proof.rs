use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ZIXCEL-TOPOLOGY-RESPONSE-AUTHENTICITY-V1\0";
const MAX_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
pub struct SignedResponseHeaders {
    pub proof_base64url: String,
    pub signature_base64url: String,
}

#[derive(Debug, Clone)]
pub(super) struct TrustPolicy {
    issuer: String,
    audience: String,
    workload_id: String,
    security_domain: String,
    deployment_id: String,
    trust_revision: u64,
    proof_key_thumbprint: String,
}

pub struct ResponseSigner {
    signing: SigningKey,
    policy: TrustPolicy,
}

#[derive(Serialize)]
struct SignedProof<'a> {
    schema: &'static str,
    algorithm: &'static str,
    issuer: &'a str,
    audience: &'a str,
    workload_id: &'a str,
    security_domain: &'a str,
    deployment_id: &'a str,
    trust_revision: u64,
    request_method: &'a str,
    request_url: &'a str,
    request_nonce: &'a str,
    response_status: u16,
    body_sha256: String,
    proof_key_thumbprint: &'a str,
    issued_at_epoch_s: u64,
    expires_at_epoch_s: u64,
}

impl ResponseSigner {
    pub(super) fn new(signing: SigningKey, policy: TrustPolicy) -> Self {
        Self { signing, policy }
    }

    /// Require the caller-configured audience exactly; it is not inferred from a request.
    pub fn accepts_audience(&self, audience: &str) -> bool {
        self.policy.audience == audience
    }

    pub fn sign(
        &self,
        method: &str,
        url: &str,
        nonce: &str,
        status: u16,
        body: &[u8],
        now_epoch_s: u64,
    ) -> Result<SignedResponseHeaders, String> {
        validate_request(method, url, nonce, status, body)?;
        let proof = SignedProof {
            schema: "zixcel://topology/signed-response-proof/v1",
            algorithm: "Ed25519",
            issuer: &self.policy.issuer,
            audience: &self.policy.audience,
            workload_id: &self.policy.workload_id,
            security_domain: &self.policy.security_domain,
            deployment_id: &self.policy.deployment_id,
            trust_revision: self.policy.trust_revision,
            request_method: method,
            request_url: url,
            request_nonce: nonce,
            response_status: status,
            body_sha256: format!("sha256:{:x}", Sha256::digest(body)),
            proof_key_thumbprint: &self.policy.proof_key_thumbprint,
            issued_at_epoch_s: now_epoch_s,
            expires_at_epoch_s: now_epoch_s
                .checked_add(30)
                .ok_or_else(|| "proof expiry overflow".to_owned())?,
        };
        let proof = serde_json::to_vec(&proof).map_err(|error| error.to_string())?;
        let signature = self.signing.sign(&signed_message(&proof, body));
        Ok(SignedResponseHeaders {
            proof_base64url: encode(&proof),
            signature_base64url: encode(&signature.to_bytes()),
        })
    }
}

impl TrustPolicy {
    pub(super) fn from_identity(
        value: &super::identity_document::PrivateIdentity,
    ) -> Result<Self, String> {
        if value.schema != "zixcel://topology/private-signing-identity/v1"
            || value.algorithm != "Ed25519"
            || value.issuer != "zixcel-topology-api"
            || !super::identity_document::safe_id(&value.audience)
            || !super::identity_document::safe_id(&value.security_domain)
            || !super::identity_document::safe_id(&value.deployment_id)
            || value.workload_id != "zixcel-topology-api"
            || value.trust_revision == 0
            || !digest(&value.proof_key_thumbprint)
        {
            return Err("private identity policy is invalid".to_owned());
        }
        Ok(Self {
            issuer: value.issuer.clone(),
            audience: value.audience.clone(),
            workload_id: value.workload_id.clone(),
            security_domain: value.security_domain.clone(),
            deployment_id: value.deployment_id.clone(),
            trust_revision: value.trust_revision,
            proof_key_thumbprint: value.proof_key_thumbprint.clone(),
        })
    }
}

pub fn signed_message(proof: &[u8], body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + 16 + proof.len() + body.len());
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(&(proof.len() as u64).to_be_bytes());
    value.extend_from_slice(&(body.len() as u64).to_be_bytes());
    value.extend_from_slice(proof);
    value.extend_from_slice(body);
    value
}

fn validate_request(
    method: &str,
    url: &str,
    nonce: &str,
    status: u16,
    body: &[u8],
) -> Result<(), String> {
    let nonce_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| "request nonce is invalid".to_owned())?;
    if method != "GET"
        || !url.starts_with("http://127.0.0.1:")
        || url.len() > 2_048
        || nonce_bytes.len() != 32
        || !(100..=599).contains(&status)
        || !(2..=MAX_BODY_BYTES).contains(&body.len())
    {
        return Err("signed topology response is outside its closed contract".to_owned());
    }
    Ok(())
}

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
