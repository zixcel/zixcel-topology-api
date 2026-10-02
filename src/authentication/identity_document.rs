use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::identity::IdentityPolicy;
use super::proof::{ResponseSigner, TrustPolicy};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateIdentity {
    pub(super) schema: String,
    pub(super) algorithm: String,
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) workload_id: String,
    pub(super) security_domain: String,
    pub(super) deployment_id: String,
    pub(super) trust_revision: u64,
    pub(super) proof_key_thumbprint: String,
    private_key_base64url: String,
    public_key_base64url: String,
}

#[derive(Serialize)]
pub(super) struct TrustBundle<'a> {
    schema: &'static str,
    algorithm: &'static str,
    issuer: &'static str,
    audience: &'a str,
    workload_id: &'static str,
    security_domain: &'a str,
    deployment_id: &'a str,
    trust_revision: u64,
    proof_key_thumbprint: &'a str,
    public_key_base64url: &'a str,
}

impl PrivateIdentity {
    pub(super) fn new(
        policy: &IdentityPolicy,
        signing: &SigningKey,
        public_text: &str,
        thumbprint: &str,
    ) -> Self {
        Self {
            schema: "zixcel://topology/private-signing-identity/v1".into(),
            algorithm: "Ed25519".into(),
            issuer: "zixcel-topology-api".into(),
            audience: policy.audience.clone(),
            workload_id: "zixcel-topology-api".into(),
            security_domain: policy.security_domain.clone(),
            deployment_id: policy.deployment_id.clone(),
            trust_revision: 1,
            proof_key_thumbprint: thumbprint.into(),
            private_key_base64url: encode(&signing.to_bytes()),
            public_key_base64url: public_text.into(),
        }
    }

    pub(super) fn validate(&self) -> Result<ResponseSigner, String> {
        let policy = TrustPolicy::from_identity(self)?;
        let signing = SigningKey::from_bytes(&decode_32(&self.private_key_base64url)?);
        let public = decode_32(&self.public_key_base64url)?;
        if signing.verifying_key()
            != VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?
            || self.proof_key_thumbprint != thumbprint(&public)
        {
            return Err("private identity key binding is invalid".to_owned());
        }
        Ok(ResponseSigner::new(signing, policy))
    }
}

impl Drop for PrivateIdentity {
    fn drop(&mut self) {
        self.private_key_base64url.zeroize();
    }
}

impl<'a> TrustBundle<'a> {
    pub(super) fn new(
        policy: &'a IdentityPolicy,
        public_text: &'a str,
        thumbprint: &'a str,
    ) -> Self {
        Self {
            schema: "zixcel://topology/response-authenticity-trust/v1",
            algorithm: "Ed25519",
            issuer: "zixcel-topology-api",
            audience: &policy.audience,
            workload_id: "zixcel-topology-api",
            security_domain: &policy.security_domain,
            deployment_id: &policy.deployment_id,
            trust_revision: 1,
            proof_key_thumbprint: thumbprint,
            public_key_base64url: public_text,
        }
    }
}

pub(super) fn validate_policy(value: &IdentityPolicy) -> Result<(), String> {
    if safe_id(&value.security_domain) && safe_id(&value.deployment_id) && safe_id(&value.audience)
    {
        Ok(())
    } else {
        Err("identity policy contains an invalid identifier".to_owned())
    }
}

pub(super) fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

pub(super) fn thumbprint(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn decode_32(value: &str) -> Result<[u8; 32], String> {
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|error| error.to_string())?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| "identity key must contain exactly 32 bytes".to_owned())
}

pub(super) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
