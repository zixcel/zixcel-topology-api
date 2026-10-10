use std::path::Path;

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::{
    ObserverError,
    secure_file::{self, FilePolicy},
};

#[derive(Clone)]
pub struct ZixcelResponseTrust {
    pub(crate) key: VerifyingKey,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) signer_id: String,
    pub(crate) security_domain: String,
    pub(crate) deployment_id: String,
    pub(crate) trust_revision: u64,
    pub(crate) thumbprint: String,
    pub(crate) request_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDocument {
    schema: String,
    algorithm: String,
    issuer: String,
    audience: String,
    workload_id: String,
    security_domain: String,
    deployment_id: String,
    trust_revision: u64,
    proof_key_thumbprint: String,
    public_key_base64url: String,
}

impl ZixcelResponseTrust {
    /// Loads a pinned response-authenticity key from an owner-only regular file.
    ///
    /// # Errors
    ///
    /// Rejects unsafe paths, unknown fields, weak keys, or policy mismatches.
    pub fn load(path: &Path, request_url: &str) -> Result<Self, ObserverError> {
        let bytes = secure_file::read(path, 8_192, FilePolicy::ProvisionedPolicy)?;
        let document: TrustDocument =
            serde_json::from_slice(&bytes).map_err(|_| ObserverError::Contract)?;
        Self::from_document(document, request_url)
    }

    fn from_document(value: TrustDocument, request_url: &str) -> Result<Self, ObserverError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&value.public_key_base64url)
            .map_err(|_| ObserverError::Contract)?;
        let key_bytes: [u8; 32] = decoded.try_into().map_err(|_| ObserverError::Contract)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| ObserverError::Contract)?;
        if value.schema != "zixcel://topology/response-authenticity-trust/v1"
            || value.algorithm != "Ed25519"
            || value.issuer != "zixcel-topology-api"
            || !identifier(&value.audience)
            || value.workload_id != "zixcel-topology-api"
            || value.trust_revision == 0
            || key.is_weak()
            || !identifier(&value.security_domain)
            || !identifier(&value.deployment_id)
            || !digest(&value.proof_key_thumbprint)
            || !allowed_url(request_url)
        {
            return Err(ObserverError::Contract);
        }
        Ok(Self {
            key,
            issuer: value.issuer,
            audience: value.audience,
            signer_id: value.workload_id,
            security_domain: value.security_domain,
            deployment_id: value.deployment_id,
            trust_revision: value.trust_revision,
            thumbprint: value.proof_key_thumbprint,
            request_url: request_url.into(),
        })
    }
}

fn allowed_url(value: &str) -> bool {
    value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(port, path)| {
            port.parse::<u16>().is_ok_and(|item| item > 0)
                && path == "v1/topology"
                && !value.contains(['?', '#', '@'])
        })
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn provisioned_audiences_are_bounded_and_cannot_inject_headers() {
        for (audience, accepted) in [
            ("coela-control".to_owned(), true),
            ("catalog-console".to_owned(), true),
            (String::new(), false),
            ("other\r\nInjected: value".to_owned(), false),
            ("other:client".to_owned(), false),
            ("a".repeat(97), false),
        ] {
            let key = SigningKey::from_bytes(&[11; 32]);
            let public = key.verifying_key().to_bytes();
            let document: TrustDocument = serde_json::from_value(serde_json::json!({
                "schema": "zixcel://topology/response-authenticity-trust/v1",
                "algorithm": "Ed25519", "issuer": "zixcel-topology-api",
                "audience": audience, "workload_id": "zixcel-topology-api",
                "security_domain": "fixture-domain", "deployment_id": "fixture-deployment",
                "trust_revision": 1, "proof_key_thumbprint": crate::sha256_digest(&public),
                "public_key_base64url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public)
            })).expect("synthetic trust document");
            let result =
                ZixcelResponseTrust::from_document(document, "http://127.0.0.1:8080/v1/topology");
            assert_eq!(result.is_ok(), accepted, "audience={audience:?}");
        }
    }
}
