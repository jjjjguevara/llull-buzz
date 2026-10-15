//! Actual lossless metadata parser controls. PostgreSQL sentinel execution remains UNRUN.
use llull_buzz_provider::inspection::history::{verify_unique, Row};
fn replay(scope: &str, event: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"relation":"resource_replays","row_sha256":"a".repeat(64),"row_key":[scope,event],"metadata":{"scope":scope,"event_id":event,"expires_at":"2026-10-07T00:00:00+00:00"}})).unwrap()
}
#[test]
fn actual_retained_parser_preserves_zero_201_1000_and_refuses_duplicate_keys() {
    verify_unique(&[]).unwrap();
    for count in [1, 201, 1000] {
        let rows = (0..count)
            .map(|index| {
                Row::parse(
                    &replay("fixed-scope", &format!("{index:064x}")),
                    "resource_replays",
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        verify_unique(&rows).unwrap();
        assert_eq!(rows.len(), count);
    }
    let first = replay("fixed-scope", &"b".repeat(64));
    let rows = vec![
        Row::parse(&first, "resource_replays").unwrap(),
        Row::parse(&first, "resource_replays").unwrap(),
    ];
    assert!(verify_unique(&rows).is_err());
}
#[test]
fn actual_unknown_source_shape_keeps_original_commitment_and_named_uncertainty() {
    let raw=serde_json::to_vec(&serde_json::json!({"relation":"task_roots","row_sha256":"b".repeat(64),"row_key":["consumer","root"],"metadata":{"consumer_id":"consumer","root_task_id":"root","root_intent_id":"intent","request_sha256":"c".repeat(64),"enrollment_id":"enrollment","created_at":"2026-10-07T00:00:00+00:00","expires_at":"2026-10-07T00:01:00+00:00","closed":false,"state":{"generation":1,"revision":1,"phase":"pending","worker":null,"stop_new_work":false},"worker_shape_valid":false,"state_shape_valid":true,"original_record_sha256":"d".repeat(64),"original_state_sha256":"e".repeat(64)}})).unwrap();
    let row = Row::parse(&raw, "task_roots").unwrap();
    assert_eq!(row.original_sha256(), "b".repeat(64));
    assert_eq!(row.uncertainties(), ["inventory-original-shape-unknown"]);
    let mut private: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    private["metadata"]["private_request_body"] = serde_json::json!("private sentinel");
    assert!(Row::parse(&serde_json::to_vec(&private).unwrap(), "task_roots").is_err());
}
#[test]
fn decoded_key_duplicates_refuse_without_unicode_normalization_or_lossy_dedup() {
    let plain = replay("a", &"c".repeat(64));
    let escaped = String::from_utf8(plain.clone())
        .unwrap()
        .replace("\"a\"", "\"\\u0061\"");
    let rows = vec![
        Row::parse(&plain, "resource_replays").unwrap(),
        Row::parse(escaped.as_bytes(), "resource_replays").unwrap(),
    ];
    assert!(verify_unique(&rows).is_err());
    let composed = replay("é", &"d".repeat(64));
    let decomposed = replay("e\u{301}", &"d".repeat(64));
    let rows = vec![
        Row::parse(&composed, "resource_replays").unwrap(),
        Row::parse(&decomposed, "resource_replays").unwrap(),
    ];
    verify_unique(&rows).unwrap();
    assert_ne!(rows[0].identity().unwrap(), rows[1].identity().unwrap());
}
