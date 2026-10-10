use sha2::{Digest, Sha256};

use crate::{ObserverError, TopologyObservationRequestV1};

/// Encodes the operation exactly as the PA body binding expects.
///
/// # Errors
///
/// Rejects values that cannot be represented by the closed JSON contract.
pub fn canonical_operation(value: &TopologyObservationRequestV1) -> Result<Vec<u8>, ObserverError> {
    serde_json::to_vec(value).map_err(|_| ObserverError::Contract)
}

/// Computes the PA-bound digest of one canonical operation.
///
/// # Errors
///
/// Rejects values that cannot be represented by the closed JSON contract.
pub fn operation_body_sha256(
    value: &TopologyObservationRequestV1,
) -> Result<String, ObserverError> {
    canonical_operation(value).map(|body| sha256_digest(&body))
}

#[must_use]
pub fn sha256_digest(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}
