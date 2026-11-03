use super::*;

fn historical_read(rig: &Rig, original: &Command) -> Command {
    let mut read = rig.command(
        "read-identity-result",
        original.resource.clone(),
        json!({"original_command":original}),
    );
    read.correlation_id = original.correlation_id.clone();
    read.causation_id = original.intent_id.clone();
    read
}

fn current_login(rig: &Rig, read: &Command, module: &str) -> Claims {
    let mut claims = rig.claims(read, module, None, None);
    let now = Utc::now().timestamp();
    claims.browser_authentication = Some(BrowserAuthentication {
        transaction_id: Uuid::new_v4().to_string(),
        authenticated_at: now,
        expires_at: now + 300,
        ..rig.browser.clone()
    });
    claims
}

async fn after_original_window(rig: &Rig) {
    let remaining = rig.browser.expires_at - Utc::now().timestamp();
    tokio::time::sleep(Duration::from_secs((remaining.max(0) + 1) as u64)).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn lost_enrollment_after_window_is_exact_read_without_new_admission() {
    let mut rig = Rig::new().await;
    rig.browser.expires_at = Utc::now().timestamp() + 3;
    let intended = nostr::Keys::generate();
    let original = rig.command(
        "enroll",
        rig.resource("principal", 1),
        Enroll {
            issuer: rig.browser.issuer.clone(),
            subject: rig.browser.subject.clone(),
            intended_public_key: intended.public_key().to_hex(),
            community_id: rig.registration.community_id.clone(),
            module_id: "module-a".into(),
            browser_transaction_id: rig.browser.transaction_id.clone(),
            native_challenge: None,
        },
    );
    let mut claims = rig.claims(&original, "module-a", None, None);
    claims.browser_authentication = Some(rig.browser.clone());
    let (body, signed) = rig.prepare("/integration/v1/enrollments", &original, &claims);
    let committed = rig.p.enroll(&body, signed.headers()).await.unwrap();
    after_original_window(&rig).await;
    // The old effect path remains closed with fresh transport credentials.
    let mut claims = rig.claims(&original, "module-a", None, None);
    claims.browser_authentication = Some(rig.browser.clone());
    let (_, signed) = rig.prepare("/integration/v1/enrollments", &original, &claims);
    assert!(rig.p.enroll(&body, signed.headers()).await.is_err());
    let read = historical_read(&rig, &original);
    let claims = current_login(&rig, &read, "module-a");
    let (body, signed) = rig.prepare("/integration/v1/identity-results", &read, &claims);
    let recovered = rig
        .p
        .identity_result(&body, signed.headers())
        .await
        .unwrap();
    assert_eq!(
        canonical(&recovered.original_result).unwrap(),
        canonical(&committed).unwrap()
    );
    assert!(recovered.current_binding.is_none());
    assert_eq!(recovered.request_sha256, original.fingerprint().unwrap());
    // A second current read also returns history, never a new challenge/effect.
    let claims = current_login(&rig, &read, "module-a");
    let (_, signed) = rig.prepare("/integration/v1/identity-results", &read, &claims);
    let again = rig
        .p
        .identity_result(&body, signed.headers())
        .await
        .unwrap();
    assert_eq!(canonical(&again).unwrap(), canonical(&recovered).unwrap());
    let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM commands WHERE consumer_id=$1), (SELECT count(*) FROM enrollment_challenges WHERE consumer_id=$1), (SELECT count(*) FROM enrollments WHERE consumer_id=$1)")
        .bind(&original.consumer_id).fetch_one(&rig.pool).await.unwrap();
    assert_eq!(counts, (1, 1, 0));

    for field in [
        "intent",
        "fingerprint",
        "scope",
        "subject",
        "context",
        "expired",
        "no-browser",
    ] {
        let mut bad = read.clone();
        if field == "intent" {
            bad.payload["original_command"]["intent_id"] = json!(Uuid::new_v4().to_string());
            bad.causation_id = bad.payload["original_command"]["intent_id"]
                .as_str()
                .unwrap()
                .into();
        }
        if field == "fingerprint" {
            bad.payload["original_command"]["payload"]["subject"] = json!("changed");
        }
        let mut claims = current_login(
            &rig,
            &bad,
            if field == "scope" {
                "module-b"
            } else {
                "module-a"
            },
        );
        if field == "subject" {
            claims.browser_authentication.as_mut().unwrap().subject = "other".into();
        }
        if field == "context" {
            claims.context_domain = "broader-domain".into();
        }
        if field == "expired" {
            claims.exp = Utc::now().timestamp() - 1;
        }
        if field == "no-browser" {
            claims.browser_authentication = None;
        }
        let (body, signed) = rig.prepare("/integration/v1/identity-results", &bad, &claims);
        let outcome = rig.p.identity_result(&body, signed.headers()).await;
        assert!(outcome.is_err(), "accepted {field}");
        if field == "intent" {
            assert!(matches!(
                outcome,
                Err(ProviderError::Admission(Fault::Unknown))
            ));
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn lost_proof_after_window_keeps_original_binding_and_current_revocation_gate() {
    let mut rig = Rig::new().await;
    rig.browser.expires_at = Utc::now().timestamp() + 4;
    let (binding, original, original_body) = rig.enroll("module-a", &nostr::Keys::generate()).await;
    let expected: serde_json::Value = sqlx::query_scalar("SELECT result FROM commands WHERE consumer_id=$1 AND operation='prove-key' AND intent_id=$2")
        .bind(&original.consumer_id).bind(&original.intent_id).fetch_one(&rig.pool).await.unwrap();
    after_original_window(&rig).await;
    let path = format!(
        "/integration/v1/enrollments/{}/proof",
        binding.enrollment_id
    );
    let mut old = rig.claims(&original, "module-a", None, None);
    old.browser_authentication = Some(rig.browser.clone());
    let (_, signed) = rig.prepare(&path, &original, &old);
    assert!(rig
        .p
        .prove_key(&binding.enrollment_id, &original_body, signed.headers())
        .await
        .is_err());
    let read = historical_read(&rig, &original);
    let claims = current_login(&rig, &read, "module-a");
    let (body, signed) = rig.prepare("/integration/v1/identity-results", &read, &claims);
    let recovered = rig
        .p
        .identity_result(&body, signed.headers())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&recovered.original_result).unwrap(),
        expected
    );
    assert_eq!(
        canonical(recovered.current_binding.as_ref().unwrap()).unwrap(),
        canonical(&binding).unwrap()
    );
    let change = rig.command(
        "change-access",
        rig.resource(&binding.enrollment_id, 1),
        ChangeAccess {
            enrollment_id: binding.enrollment_id.clone(),
            expected_revision: "1".into(),
            change: AccessChange::Revoke,
        },
    );
    let claims = rig.claims(&change, "module-a", None, None);
    let (change_body, signed) = rig.prepare("/integration/v1/access-changes", &change, &claims);
    rig.p
        .change_access(&change_body, signed.headers())
        .await
        .unwrap();
    let claims = current_login(&rig, &read, "module-a");
    let (_, signed) = rig.prepare("/integration/v1/identity-results", &read, &claims);
    assert!(rig
        .p
        .identity_result(&body, signed.headers())
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM commands WHERE consumer_id=$1 AND operation='prove-key'",
    )
    .bind(&original.consumer_id)
    .fetch_one(&rig.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    // Restarting the service object preserves the same revoked result gate.
    let restarted =
        Provider::new(rig.pool.clone(), "https://provider.synthetic.invalid", 1).unwrap();
    let claims = current_login(&rig, &read, "module-a");
    let (_, signed) = rig.prepare("/integration/v1/identity-results", &read, &claims);
    assert!(restarted
        .identity_result(&body, signed.headers())
        .await
        .is_err());
}
