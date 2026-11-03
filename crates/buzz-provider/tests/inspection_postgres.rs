//! AUTHORED UNRUN: concrete PostgreSQL controls, ignored by every default gate.
//! Explicit isolated fixture authorization is required even with --ignored.
//! These methods never fabricate installed standing or qualified receipts.
use llull_buzz_provider::inspection::relations;
use sqlx::{Connection, Executor, Row};
async fn isolated(selector: &str, expected_role: &str) -> sqlx::PgConnection {
    assert_eq!(
        std::env::var("BUZZ_INSPECTION_NATIVE").as_deref(),
        Ok("authorized-isolated"),
        "native fixture authorization absent"
    );
    let url = std::env::var(selector).expect("explicit isolated fixture URL absent");
    // Fixture credentials are never logged or included in assertion messages.
    let mut sql = sqlx::PgConnection::connect(&url)
        .await
        .expect("native connection failed");
    let row = sqlx::query("SELECT current_database() AS db,current_user AS role")
        .fetch_one(&mut sql)
        .await
        .unwrap();
    assert!(row
        .get::<String, _>("db")
        .starts_with("buzz_inspection_test_"));
    if !expected_role.is_empty() {
        assert_eq!(row.get::<String, _>("role"), expected_role);
    }
    sql
}
fn denied(error: sqlx::Error) {
    let code = error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "native role lacked expected privilege refusal"
    );
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: isolated installed inspector roles and TLS fixture required"]
async fn installed_inspector_cannot_read_secrets_mutate_create_or_set_owner_role() {
    let mut sql = isolated(
        "BUZZ_INSPECTION_NATIVE_INSPECTOR_URL",
        "buzz_recovery_inspector",
    )
    .await;
    for statement in [
        "SELECT secret FROM public.observation_keys",
        "SELECT request_bytes FROM public.attempts",
        "SELECT signed_event FROM public.publication_deliveries",
        "SELECT invocation_jws FROM public.admission_evidence",
        "SELECT request FROM public.model_dispatches",
        "SELECT bytes FROM public.native_attachments",
        "SELECT claims FROM public.native_attachment_leases",
        "INSERT INTO public.provider_control(singleton,recovery_epoch) VALUES(2,1)",
        "UPDATE public.provider_control SET recovery_epoch=recovery_epoch WHERE singleton=1",
        "DELETE FROM public.provider_control WHERE singleton=1",
        "CREATE SCHEMA inspection_unauthorized_create",
        "CREATE TEMP TABLE inspection_unauthorized_temp(x integer)",
        "SET ROLE buzz_recovery_view_owner",
    ] {
        // Every attempt owns a transaction; even contrary successful mutations
        // are rolled back before the assertion can terminate the method.
        sql.execute("BEGIN").await.unwrap();
        sql.execute("SET TRANSACTION READ WRITE").await.unwrap();
        let result = sql.execute(statement).await;
        sql.execute("ROLLBACK").await.unwrap();
        denied(result.expect_err("unexpected inspector capability"));
    }
    for relation in relations::RELATIONS {
        let statement = format!(
            "SELECT row_sha256,row_key,metadata FROM buzz_inspection.v_{} LIMIT 0",
            relation.name
        );
        // Identifiers come only from the fixed relation registry above.
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut sql)
            .await
            .unwrap();
    }
    sql.close().await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: isolated admin fixture and prepared migration required"]
async fn original_server_commitment_retained_while_nested_private_sentinel_is_absent() {
    let mut sql = isolated("BUZZ_INSPECTION_NATIVE_ADMIN_URL", "").await;
    sql.execute("BEGIN").await.unwrap();
    let consumer = format!("inspection-native-{}", uuid::Uuid::new_v4());
    let registration = serde_json::json!({"consumer_id":consumer,"revision":1,"policy_revision":"fixture-policy","authority_epoch":1,
        "community_id":"fixture-community","service_principal":"fixture-service","service_public_key":"a".repeat(64),
        "enrollment_bot_key":"b".repeat(64),"enrollment_channel":"fixture-channel","issuer":"https://fixture.invalid",
        "audiences":{},"verification_keys":{},"retention":{},"pricing":null,"modules":{"fixture-module":{"actions":["read"],
            "principal_issuers":["https://fixture.invalid"],"context_domains":["fixture-context"],"task_schemas":["fixture-task"],
            "tools":{"fixture-tool":{"action":"read","schema_sha256":"c".repeat(64),"effect_owner":"fixture-owner",
                "requires_verdict":false,"unexpected_private":"DO_NOT_EXPORT_PRIVATE_SENTINEL"}}}}});
    sqlx::query("INSERT INTO public.consumer_registry(consumer_id,revision,registration,registration_sha256) VALUES($1,1,$2,$3)")
        .bind(&consumer).bind(sqlx::types::Json(registration)).bind("d".repeat(64)).execute(&mut sql).await.unwrap();
    let original:String=sqlx::query_scalar("SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') FROM public.consumer_registry r WHERE consumer_id=$1").bind(&consumer).fetch_one(&mut sql).await.unwrap();
    sql.execute("SET LOCAL ROLE buzz_recovery_inspector")
        .await
        .unwrap();
    let view=sqlx::query("SELECT row_sha256,metadata::text AS metadata FROM buzz_inspection.v_consumer_registry WHERE metadata->>'consumer_id'=$1").bind(&consumer).fetch_one(&mut sql).await.unwrap();
    assert_eq!(view.get::<String, _>("row_sha256"), original);
    let metadata: String = view.get("metadata");
    assert!(!metadata.contains("DO_NOT_EXPORT_PRIVATE_SENTINEL"));
    let value: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    assert_eq!(value["modules_shape_valid"], false);
    sql.execute("ROLLBACK").await.unwrap();
    sql.close().await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: isolated admin fixture; real portal/snapshot qualification required"]
async fn real_without_hold_cursor_custody_preserves_201_and_1000_then_eof() {
    let mut sql = isolated("BUZZ_INSPECTION_NATIVE_ADMIN_URL", "").await;
    // Synthetic fixture inserts are owned by one transaction and always rolled
    // back. No existing business rows are changed or discarded.
    for count in [201i64, 1000i64] {
        sql.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .unwrap();
        let scope = format!("inspection-native-{}", uuid::Uuid::new_v4());
        sqlx::query("INSERT INTO public.resource_replays(scope,event_id,expires_at) SELECT $1,lpad(to_hex(n),64,'0'),clock_timestamp()+interval '1 hour' FROM generate_series(1,$2) n").bind(&scope).bind(count).execute(&mut sql).await.unwrap();
        let before: String = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
            .fetch_one(&mut sql)
            .await
            .unwrap();
        sql.execute("SET LOCAL ROLE buzz_recovery_inspector")
            .await
            .unwrap();
        // Bound filter only selects the synthetic test scope. Production uses
        // all 27 fixed relations without a caller filter; its source gate is separate.
        sql.execute("DECLARE inspection_native NO SCROLL CURSOR WITHOUT HOLD FOR SELECT metadata->>'scope' AS scope,metadata->>'event_id' AS event_id FROM buzz_inspection.v_resource_replays ORDER BY row_key::text COLLATE \"C\"").await.unwrap();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(row) = sqlx::query("FETCH FORWARD 1 FROM inspection_native")
            .fetch_optional(&mut sql)
            .await
            .unwrap()
        {
            if row.get::<String, _>("scope") == scope {
                assert!(seen.insert(row.get::<String, _>("event_id")));
            }
        }
        assert_eq!(seen.len() as i64, count);
        let after: String = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
            .fetch_one(&mut sql)
            .await
            .unwrap();
        assert_eq!(before, after);
        sql.execute("CLOSE inspection_native").await.unwrap();
        sql.execute("ROLLBACK").await.unwrap();
    }
    sql.close().await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: installed dedicated role/catalog fixture required"]
async fn actual_effective_public_and_inherited_application_privileges_are_absent() {
    let mut sql = isolated(
        "BUZZ_INSPECTION_NATIVE_INSPECTOR_URL",
        "buzz_recovery_inspector",
    )
    .await;
    let flags=sqlx::query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetch_one(&mut sql).await.unwrap();
    for key in [
        "rolsuper",
        "rolcreatedb",
        "rolcreaterole",
        "rolinherit",
        "rolreplication",
        "rolbypassrls",
    ] {
        assert!(!flags.get::<bool, _>(key));
    }
    let memberships:i64=sqlx::query_scalar("SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)").fetch_one(&mut sql).await.unwrap();
    assert_eq!(memberships, 0);
    let executable:i64=sqlx::query_scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetch_one(&mut sql).await.unwrap();
    assert_eq!(executable, 0);
    let temporary: bool = sqlx::query_scalar(
        "SELECT has_database_privilege(current_user,current_database(),'TEMPORARY')",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    assert!(!temporary);
    let create: bool = sqlx::query_scalar(
        "SELECT has_database_privilege(current_user,current_database(),'CREATE')",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    assert!(!create);
    let database_owner: bool = sqlx::query_scalar(
        "SELECT d.datdba IN (SELECT oid FROM pg_roles WHERE rolname IN ('buzz_recovery_inspector','buzz_recovery_view_owner')) FROM pg_database d WHERE d.datname=current_database()",
    ).fetch_one(&mut sql).await.unwrap();
    assert!(!database_owner);
    sql.close().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: fresh isolated baseline-only admin fixture required"]
async fn prepared_forward_migration_preserves_existing_runtime_effective_privileges() {
    let mut sql = isolated("BUZZ_INSPECTION_NATIVE_ADMIN_URL", "").await;
    let occupied:i64=sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname IN ('buzz_recovery_inspector','buzz_recovery_view_owner')").fetch_one(&mut sql).await.unwrap();
    assert_eq!(occupied, 0, "requires isolated baseline-only fixture");
    // No passwords, base data, ACL bodies or private tenant contents are read.
    const MATRIX:&str="SELECT jsonb_agg(fact ORDER BY fact::text COLLATE \"C\")::text FROM (SELECT jsonb_build_object('role',r.rolname,'database',has_database_privilege(r.oid,current_database(),'TEMPORARY'),'database_create',has_database_privilege(r.oid,current_database(),'CREATE'),'functions',(SELECT jsonb_object_agg(p.oid::text,has_function_privilege(r.oid,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),'tables',(SELECT jsonb_object_agg(c.oid::text,jsonb_build_object('select',has_table_privilege(r.oid,c.oid,'SELECT'),'insert',has_table_privilege(r.oid,c.oid,'INSERT'),'update',has_table_privilege(r.oid,c.oid,'UPDATE'),'delete',has_table_privilege(r.oid,c.oid,'DELETE'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f'))) AS fact FROM pg_roles r WHERE r.rolname NOT IN ('buzz_recovery_inspector','buzz_recovery_view_owner')) facts";
    let before: String = sqlx::query_scalar(MATRIX)
        .fetch_one(&mut sql)
        .await
        .unwrap();
    sql.execute("BEGIN").await.unwrap();
    let migrated = sqlx::raw_sql(concat!(
        include_str!("../../../migrations/0009_private_metadata_inspection.sql"),
        "\n",
        include_str!("../../../migrations/0010_private_authority_inspection.sql")
    ))
    .execute(&mut sql)
    .await;
    let after = if migrated.is_ok() {
        sqlx::query_scalar::<_, String>(MATRIX)
            .fetch_one(&mut sql)
            .await
    } else {
        Err(sqlx::Error::Protocol("prepared migration refused".into()))
    };
    // Role creation, ACLs and views are all transaction-owned in this isolated
    // method. Native rollback precedes every contrary-result assertion.
    sql.execute("ROLLBACK").await.unwrap();
    sql.close().await.unwrap();
    migrated.unwrap();
    assert_eq!(before, after.unwrap());
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "AUTHORED UNRUN: isolated fixed /etc/llull-buzz/inspection profile, fresh signed request, TLS and retained-output fixture required"]
async fn installed_production_constructor_reaches_exact_session_and_retained_receipt() {
    // The fixed installed profile must name the same isolated database checked
    // by the native fixture owner. No hand-written Session header or alternate
    // connection-options builder substitutes for NativeSession::connect here.
    use base64::Engine;
    use std::io::Read;
    let mut sql = isolated(
        "BUZZ_INSPECTION_NATIVE_INSPECTOR_URL",
        "buzz_recovery_inspector",
    )
    .await;
    let actual = sqlx::query("SELECT current_database() AS name,(SELECT oid::bigint FROM pg_database WHERE datname=current_database()) AS oid,inet_server_addr()::text AS address,inet_server_port() AS port").fetch_one(&mut sql).await.unwrap();
    sql.close().await.unwrap();
    assert_eq!(
        std::env::var("BUZZ_INSPECTION_NATIVE_FIXED_PROFILE").as_deref(),
        Ok("authorized-isolated")
    );
    // Extra fixture-scope guard only, never profile authentication. The genuine
    // port reopens no-follow and authenticates every byte/key/binding itself.
    let mut profile = Vec::new();
    std::fs::File::open("/etc/llull-buzz/inspection/profile.jws")
        .unwrap()
        .take(llull_buzz_wire::MAX_BYTES as u64 + 1)
        .read_to_end(&mut profile)
        .unwrap();
    assert!(profile.len() <= llull_buzz_wire::MAX_BYTES);
    let token = std::str::from_utf8(&profile).unwrap();
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).unwrap())
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload["body"]["database"]["database"].as_str(),
        Some(actual.get::<String, _>("name").as_str())
    );
    assert_eq!(
        payload["body"]["database"]["database_oid"].as_i64(),
        Some(actual.get::<i64, _>("oid"))
    );
    assert_eq!(
        payload["body"]["database"]["server_address"].as_str(),
        Some(actual.get::<String, _>("address").as_str())
    );
    assert_eq!(
        payload["body"]["database"]["port"].as_i64(),
        Some(actual.get::<i32, _>("port") as i64)
    );
    let receipt = llull_buzz_provider::inspection::port::run_local(std::future::pending())
        .await
        .expect("actual production options/session/catalog path refused");
    assert_eq!(receipt.filename.len(), 68);
    assert!(receipt.filename.ends_with(".jws"));
    assert!(receipt.filename[..64]
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    // Successful response pages are retained native evidence, not scratch to
    // delete by guessed filenames. run_local owns their private custody proof.
}
