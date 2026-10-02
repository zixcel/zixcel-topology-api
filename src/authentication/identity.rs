use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::identity_document::{PrivateIdentity, TrustBundle, encode, thumbprint, validate_policy};
use super::proof::ResponseSigner;
use super::secure_path::{secure_file, secure_parent, write_new};

#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    pub audience: String,
    pub security_domain: String,
    pub deployment_id: String,
}

pub fn generate_identity(
    private_path: &Path,
    trust_path: &Path,
    policy: &IdentityPolicy,
) -> Result<(), String> {
    validate_policy(policy)?;
    secure_parent(private_path)?;
    secure_parent(trust_path)?;
    if private_path.exists() || trust_path.exists() {
        return Err("topology identity already exists; rotation must be explicit".to_owned());
    }
    let signing = SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key().to_bytes();
    let public_text = encode(&public);
    let thumbprint = thumbprint(&public);
    let private = PrivateIdentity::new(policy, &signing, &public_text, &thumbprint);
    let trust = TrustBundle::new(policy, &public_text, &thumbprint);
    let private_bytes = Zeroizing::new(serde_json::to_vec(&private).map_err(text)?);
    let trust_bytes = serde_json::to_vec(&trust).map_err(text)?;
    write_new(private_path, &private_bytes, 0o600)?;
    if let Err(error) = write_new(trust_path, &trust_bytes, 0o600) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }
    Ok(())
}

impl ResponseSigner {
    pub fn load(path: &Path) -> Result<Self, String> {
        secure_file(path, 0o600)?;
        let bytes = Zeroizing::new(fs::read(path).map_err(text)?);
        if bytes.len() > 8_192 {
            return Err("private identity exceeds 8 KiB".to_owned());
        }
        let value: PrivateIdentity = serde_json::from_slice(&bytes).map_err(text)?;
        value.validate()
    }
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
