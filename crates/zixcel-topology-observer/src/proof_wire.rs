use base64::Engine;

use crate::ObserverError;

const DOMAIN: &[u8] = b"ZIXCEL-TOPOLOGY-RESPONSE-AUTHENTICITY-V1\0";

pub(crate) fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, ObserverError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(ObserverError::ResponseAuthenticity);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ObserverError::ResponseAuthenticity)?;
    if decoded.len() > maximum
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(ObserverError::ResponseAuthenticity);
    }
    Ok(decoded)
}

pub(crate) fn signed_message(proof: &[u8], body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + 16 + proof.len() + body.len());
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(&(proof.len() as u64).to_be_bytes());
    value.extend_from_slice(&(body.len() as u64).to_be_bytes());
    value.extend_from_slice(proof);
    value.extend_from_slice(body);
    value
}
