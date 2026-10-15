//! Source controls: SQL plans are inspected here; actual PostgreSQL is separately UNRUN.
use llull_buzz_provider::inspection::{clock::Budget, json::validate_raw, relations};
#[test]
fn complete_fixed_relation_set_and_server_original_commitments() {
    assert_eq!(relations::RELATIONS.len(), 27);
    let mut names = std::collections::BTreeSet::new();
    for relation in relations::RELATIONS {
        assert!(names.insert(relation.name));
        let view = relation.view_sql();
        assert!(view.contains("security_barrier = true"));
        assert!(view.contains("to_jsonb(r)::text"));
        assert!(view.contains("sha256(convert_to("));
        assert!(view.contains("'UTF8'"));
        assert!(view.contains("row_sha256"));
        assert!(!view.contains("r.*"));
    }
    assert!(relations::relation("unknown").is_err());
}
#[test]
fn nested_worker_is_closed_and_never_forwarded_wholesale() {
    let view = relations::relation("task_roots").unwrap().view_sql();
    assert!(!view.contains("'worker',r.state->'worker')"));
    for field in ["owner", "generation", "lease_until"] {
        assert!(view.contains(field));
    }
    assert!(view.contains("worker_shape_valid"));
    assert!(view.contains("state_sha256"));
}
#[test]
fn original_private_bodies_have_only_server_commitments() {
    for (table, column) in [
        ("observation_keys", "secret"),
        ("attempts", "request_bytes"),
        ("publication_deliveries", "signed_event"),
        ("admission_evidence", "invocation_jws"),
    ] {
        let view = relations::relation(table).unwrap().view_sql();
        assert!(!view.contains(&format!("'{}',r.{}", column, column)));
        assert!(view.contains(&format!("original_{}_sha256", column)));
    }
}
#[test]
fn lossless_sql_json_retains_large_numbers_and_unicode_but_denies_ambiguity() {
    let raw=br#"{"revision":9007199254740993,"quota":0.123456789012345678901234567890,"empty":null,"name":" e\u0301 "}"#;
    assert!(validate_raw(raw).is_ok());
    assert!(llull_buzz_provider::wire::parse::<serde_json::Value>(raw).is_err());
    for bad in [
        br#"{"a":1,"\u0061":2}"#.as_slice(),
        br#"{"a":{"b":1,"b":2}}"#,
        b"[1] null",
        &[0xff],
    ] {
        assert!(validate_raw(bad).is_err());
    }
}
#[test]
fn cumulative_clock_boundary_regression_and_sticky_failure() {
    let mut b = Budget::new(1_000, 30_000_000).unwrap();
    assert!(b.sample(20_001_000).is_ok());
    assert!(b.sample(20_001_001).is_err());
    assert!(b.sample(1_000).is_err());
    let mut b = Budget::new(1_000, 30_000_000).unwrap();
    assert!(b.sample(999).is_err());
    assert!(b.sample(1_001).is_err());
    let mut b = Budget::new(1_000, 1_005).unwrap();
    assert!(b.sample(1_004).is_ok());
    assert!(b.sample(1_005).is_err());
}

#[test]
fn lawful_full_aggregate_single_row_stays_lossless() {
    let prefix = b"{\"payload\":\"";
    let suffix = b"\"}";
    let mut raw = Vec::with_capacity(llull_buzz_provider::inspection::json::MAX_RAW_BYTES);
    raw.extend_from_slice(prefix);
    raw.resize(
        llull_buzz_provider::inspection::json::MAX_RAW_BYTES - suffix.len(),
        b'a',
    );
    raw.extend_from_slice(suffix);
    assert_eq!(raw.len(), 2 * 1024 * 1024);
    assert!(validate_raw(&raw).is_ok());
    assert_eq!(llull_buzz_provider::wire::MAX_BYTES, 1024 * 1024);
    assert!(llull_buzz_provider::wire::parse::<serde_json::Value>(&raw).is_err());
    raw.push(b' ');
    assert!(validate_raw(&raw).is_err());
}

#[test]
fn forward_migration_keeps_current_runtime_privilege_preservation_and_private_scope() {
    let sql = include_str!("../../../migrations/0009_private_metadata_inspection.sql");
    for function in [
        "deny_history_mutation",
        "freeze_root_identity",
        "freeze_attempt_identity",
        "freeze_binding_identity",
        "freeze_publication_delivery",
        "freeze_model_dispatch",
    ] {
        assert!(sql.contains(&format!("'{function}'")));
    }
    let capture = sql
        .find("has_function_privilege(oid,routine.oid,'EXECUTE')")
        .unwrap();
    let preserve = sql
        .find("GRANT EXECUTE ON FUNCTION %I.%I(%s) TO %I")
        .unwrap();
    let revoke = sql
        .find("REVOKE EXECUTE ON FUNCTION %I.%I(%s) FROM PUBLIC")
        .unwrap();
    assert!(capture < preserve && preserve < revoke);
    assert!(sql.contains("rolname NOT IN ('buzz_recovery_inspector','buzz_recovery_view_owner')"));
    for relation in relations::RELATIONS {
        assert!(sql.contains(relation.view_sql()));
    }
    for name in [
        "model_dispatches",
        "native_attachments",
        "native_attachment_leases",
    ] {
        assert!(relations::relation(name).is_err());
        assert!(!sql.contains(&format!("GRANT SELECT ON public.{name} ")));
        assert!(!sql.contains(&format!("CREATE VIEW buzz_inspection.v_{name} ")));
    }
    assert_eq!(sql.matches("CREATE VIEW buzz_inspection.").count(), 27);
}
