use super::*;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16"]
async fn discovery_is_authenticated_scoped_and_revision_bound() {
    let rig = Rig::new().await;
    let mut request = rig.command("discover-profile", rig.resource("profile", 1), json!({}));
    request.intent_id = "profile".into();
    let mut claims = rig.claims(&request, "module-a", None, None);
    claims.payload_sha256 = sha256(b"");
    let path = "/integration/v1/profile";
    let h = rig.sign(path, "GET", b"", &claims, INVOCATION);
    let result = rig
        .p
        .discover_profile(&request.consumer_id, h.headers())
        .await
        .unwrap();
    assert_eq!(result.contract, CONTRACT);
    assert_eq!(result.profile, PROFILE);
    assert_eq!(result.module_id, "module-a");
    assert_eq!(result.registration_revision, 1);
    assert_eq!(
        result.wire_schema_sha256,
        sha256(include_bytes!(
            "../../../../docs/architecture/contracts/schemas/buzz-wire-v1.schema.json"
        ))
    );
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("PUBLIC KEY"));
    assert!(rig
        .p
        .discover_profile(&request.consumer_id, h.headers())
        .await
        .is_err());

    claims.jti = Uuid::new_v4().to_string();
    let h = rig.sign(path, "GET", b"", &claims, INVOCATION);
    assert!(rig
        .p
        .discover_profile("unregistered-consumer", h.headers())
        .await
        .is_err());
    rig.p
        .set_service_active(
            &request.consumer_id,
            false,
            &digest(&rig.registration).unwrap(),
        )
        .await
        .unwrap();
    assert!(rig
        .p
        .discover_profile(&request.consumer_id, h.headers())
        .await
        .is_err());
}
