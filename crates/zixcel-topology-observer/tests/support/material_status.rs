fn current_status(document: &ControlAuthorizationV2) -> CurrentDeviceStatusV1 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("status clock")
        .as_secs();
    let mut status = CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: "ihat://identity-authority".into(),
        audience: "crowsi://topology-observer/current-status".into(),
        service_id: document.service_id.clone(),
        pairwise_subject: document.pairwise_subject.clone(),
        device_id: document.device_id.clone(),
        device_proof_key_ref: document.device_proof_key_ref.clone(),
        session_ref: document.session_ref.clone(),
        device_posture: DevicePostureV1 {
            state: document.device_posture.clone(),
            revision: document.device_posture_revision,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: document.subject_revocation_epoch,
            service: document.service_revocation_epoch,
            device: document.device_revocation_epoch,
            session: document.session_revocation_epoch,
        },
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 30,
        nonce: "status-topology-fixture-001".into(),
        key_id: "ihat-status-key:topology-fixture:1".into(),
        signature: String::new(),
    };
    let signer = SigningKey::from_bytes(&[9; 32]);
    status.signature = hex::encode(
        signer
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    status
}
