//! Original synthetic native-owner signatures and fixed-origin HTTP controls.
//! These controls do not supply a named desktop/mobile human UAT verdict.
use super::*;
use crate::{EnrollmentDirectoryPort, HttpNativeOrigin};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TrackedDirectoryCredential {
    root: std::path::PathBuf,
    credential: std::sync::Arc<crate::native_custody::NativeCredential>,
}

impl Drop for TrackedDirectoryCredential {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

fn tracked_native_source(
    community: &str,
    private: &str,
    public: &str,
    key: &nostr::Keys,
    relay: nostr::PublicKey,
) -> (TrackedDirectoryCredential, HttpNativeOrigin) {
    use crate::native_custody::{NativeCredential, NativeCustodyScope, ProcessIncarnation};
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "buzz-enrollment-admission-{}",
        uuid::Uuid::new_v4()
    ));
    let logs = root.join("logs");
    let keys = root.join("keys");
    for path in [&root, &logs, &keys] {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let file = keys.join("synthetic.key");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .unwrap();
    output
        .write_all(key.secret_key().to_secret_hex().as_bytes())
        .unwrap();
    output.sync_all().unwrap();
    drop(output);
    let configuration = json!({"community":community,"private":private,"public":public,"service":key.public_key().to_hex(),"relay":relay.to_hex()});
    let scope = NativeCustodyScope {
        kind: "llull-buzz-native-custody-scope/v1".into(),
        custody_id: uuid::Uuid::new_v4().simple().to_string(),
        installation: "synthetic-enrollment-native-owner".into(),
        // The native-owner contract source is pinned; this synthetic scope is
        // not a provider build/release attestation or a live permission grant.
        source_revision: llull_buzz_wire::UPSTREAM.into(),
        implementation_sha256: crate::inspection::relations::implementation_sha256(),
        membership_sha256: llull_buzz_wire::sha256(
            b"synthetic explicitly admitted native moderator",
        ),
        operation_ref: "synthetic-enrollment-native-read".into(),
        operation_sha256: llull_buzz_wire::sha256(b"synthetic exact native admission read"),
        configuration_sha256: llull_buzz_wire::digest(&configuration).unwrap(),
        configuration_generation: 1,
        source_copy_sha256: llull_buzz_wire::sha256(b"synthetic source"),
        target_copy_sha256: llull_buzz_wire::sha256(b"synthetic target"),
        community_id: community.into(),
        private_origin: private.into(),
        public_origin: public.into(),
        relay_public_key: relay.to_hex(),
        credential_public_key: key.public_key().to_hex(),
        credential_file: file.to_str().unwrap().into(),
    };
    let credential = NativeCredential::acquire_synthetic_fixture(
        scope,
        &file,
        &logs,
        ProcessIncarnation::current,
    )
    .unwrap();
    let source = HttpNativeOrigin::with_signer(
        community.into(),
        private,
        public,
        credential.signer("native-http").unwrap(),
        relay,
    )
    .unwrap()
    .with_enrollment_admission_signer(credential.signer("native-enrollment-admission").unwrap())
    .unwrap();
    (TrackedDirectoryCredential { root, credential }, source)
}

fn synthetic_admission(
    community: &str,
    intended: &str,
    moderator: &nostr::Keys,
) -> NativeEnrollmentAdmissionCheck {
    let endpoint = "https://native-owner.synthetic.invalid/moderation/restricted";
    let request = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
        .tags([
            nostr::Tag::parse(["u", endpoint]).unwrap(),
            nostr::Tag::parse(["method", "GET"]).unwrap(),
            nostr::Tag::parse(["payload", llull_buzz_wire::sha256(b"").as_str()]).unwrap(),
            nostr::Tag::parse(["nonce", uuid::Uuid::new_v4().to_string().as_str()]).unwrap(),
        ])
        .sign_with_keys(moderator)
        .unwrap();
    let checked_at = Utc::now();
    NativeEnrollmentAdmissionCheck {
        kind: "llull-buzz-native-enrollment-admission/v1".into(),
        community_id: community.into(),
        intended_public_key: intended.into(),
        moderation_endpoint: endpoint.into(),
        request_event_id: request.id.to_hex(),
        response_sha256: llull_buzz_wire::sha256(b"[]"),
        checked_at,
        valid_until: checked_at + ChronoDuration::seconds(ENROLLMENT_ADMISSION_SECONDS),
    }
}

struct DirectoryFixture {
    relay: nostr::Keys,
    intended: nostr::Keys,
    bot: nostr::Keys,
    view: NativeEnrollmentView,
}

fn signed(key: &nostr::Keys, kind: u16, tags: Vec<Vec<String>>, content: &str) -> Value {
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(kind), content)
        .tags(tags.iter().map(|fields| nostr::Tag::parse(fields).unwrap()))
        .custom_created_at(nostr::Timestamp::from(1_800_000_000))
        .sign_with_keys(key)
        .unwrap();
    serde_json::to_value(event).unwrap()
}

fn tags(values: &[&[&str]]) -> Vec<Vec<String>> {
    values
        .iter()
        .map(|fields| fields.iter().map(|value| (*value).to_owned()).collect())
        .collect()
}

fn fixture(nip43: bool) -> DirectoryFixture {
    let relay = nostr::Keys::generate();
    let intended = nostr::Keys::generate();
    let bot = nostr::Keys::generate();
    let channel = uuid::Uuid::new_v4().to_string();
    let intended_key = intended.public_key().to_hex();
    let bot_key = bot.public_key().to_hex();
    let relay_key = relay.public_key().to_hex();
    let metadata = signed(
        &relay,
        39000,
        tags(&[
            &["d", &channel],
            &["name", "Enrollment"],
            &["t", "stream"],
            &["private"],
            &["closed"],
        ]),
        "",
    );
    let roster = signed(
        &relay,
        39002,
        tags(&[
            &["d", &channel],
            &["p", &intended_key, "", "member"],
            &["p", &bot_key, "", "bot"],
        ]),
        "",
    );
    let profiles = vec![
        signed(
            &intended,
            0,
            vec![],
            &json!({"display_name":"Fixture Human","about":"Native account already exists"})
                .to_string(),
        ),
        signed(
            &bot,
            0,
            vec![],
            &json!({"display_name":"enrollment_bot","name":"ignored_fallback"}).to_string(),
        ),
    ];
    let relay_membership = nip43.then(|| {
        signed(
            &relay,
            13534,
            tags(&[
                &["member", &intended_key, "member"],
                &["member", &bot_key, "member"],
            ]),
            "",
        )
    });
    let view = NativeEnrollmentView {
        community_id: "native-fixture-community".into(),
        channel_id: channel,
        intended_public_key: intended_key.clone(),
        bot_public_key: bot_key,
        relay_public_key: relay_key.clone(),
        channel_metadata: metadata,
        channel_membership: roster,
        profiles,
        relay_information: json!({"self":relay_key,"supported_nips":if nip43 { vec![1,11,29,42,43,98] } else { vec![1,11,29,42,98] },"pairing_relay_url":"wss://pairing.synthetic.invalid/pair"}),
        relay_membership,
        join_policy: Some(
            json!({"policy":{"terms_markdown":"Native terms","privacy_markdown":"Native privacy","age_attestation_required":true,"version":"owner-policy-v1"}}),
        ),
        admission_check: synthetic_admission("native-fixture-community", &intended_key, &relay),
    };
    DirectoryFixture {
        relay,
        intended,
        bot,
        view,
    }
}

#[test]
fn original_native_directory_preserves_owner_records_and_profile_identity() {
    let fixture = fixture(true);
    let view = &fixture.view;
    view.validate().unwrap();
    view.validate_bot_mention("@enrollment_bot").unwrap();
    let values = view
        .query(
            &json!([
                {"kinds":[39002],"#p":[view.intended_public_key],"limit":500},
                {"kinds":[39000],"#d":[view.channel_id],"limit":1},
                {"kinds":[0],"authors":[view.intended_public_key,view.bot_public_key],"limit":2},
                {"kinds":[13534],"limit":1},
            ]),
            None,
        )
        .unwrap();
    assert_eq!(values.len(), 5);
    for original in [
        &view.channel_metadata,
        &view.channel_membership,
        &view.profiles[0],
        &view.profiles[1],
        view.relay_membership.as_ref().unwrap(),
    ] {
        assert!(
            values.contains(original),
            "the full signed native record must remain unchanged"
        );
    }
    // The ordinary global channel-directory query exposes this one configured
    // enrollment channel, never a new general native source query.
    assert_eq!(
        view.query(&json!([{"kinds":[39000],"limit":500}]), None)
            .unwrap(),
        vec![view.channel_metadata.clone()]
    );
}

#[test]
fn gateway_descriptor_declares_only_implemented_scope_limits_and_owner_provenance() {
    let mut data = fixture(true);
    data.view.relay_information["supported_nips"] = json!([1, 9, 11, 29, 42, 43, 50, 98]);
    data.view.relay_information["limitation"] =
        json!({"max_subscriptions":1024,"max_filters":10,"max_message_length":524288});
    data.view.relay_information["extensions"] = json!({"buzz":{"gifs":{"api":"/api/gifs"},"push":{"api":"/api/push"}},"uploads":{"api":"/media"}});
    data.view.relay_information["push"] = json!({"enabled":true});
    data.view.relay_information["software"] = json!("original-full-native-owner");
    data.view.relay_information["pubkey"] = json!(data.relay.public_key().to_hex());
    data.view.relay_information["contact"] = json!("synthetic-owner@example.invalid");
    let original = data.view.relay_information.clone();
    let descriptor = data.view.gateway_information().unwrap();
    assert_eq!(descriptor["self"], original["self"]);
    assert_eq!(descriptor["pubkey"], original["pubkey"]);
    assert_eq!(descriptor["contact"], original["contact"]);
    assert_eq!(
        descriptor["native_owner"], original,
        "native owner's complete public declaration is named provenance, not gateway support"
    );
    assert_eq!(descriptor["supported_nips"], json!([1, 11, 42, 43, 98]));
    assert_eq!(descriptor["limitation"]["max_filters"], 8);
    assert_eq!(descriptor["limitation"]["max_message_length"], 65_536);
    assert_eq!(descriptor["limitation"]["max_subscriptions"], 0);
    assert_eq!(
        descriptor["enrollment_gateway"]["http_query_max_filters"],
        16
    );
    assert_eq!(
        descriptor["enrollment_gateway"]["max_frames_per_connection"],
        64
    );
    assert_eq!(descriptor["enrollment_gateway"]["read_mode"], "one-shot");
    assert_eq!(
        descriptor["enrollment_gateway"]["native_membership"],
        "original-owner-read-only-required"
    );
    for name in ["extensions", "push", "gifs", "media", "software"] {
        assert!(
            descriptor.get(name).is_none(),
            "original owner's {name} must not be advertised as a gateway API"
        );
    }
    for name in [
        "persistent_subscriptions",
        "push",
        "gifs",
        "media",
        "channel_join",
        "channel_management",
        "membership_administration",
        "general_publication",
    ] {
        assert_eq!(descriptor["enrollment_gateway"][name], false);
    }
    assert_eq!(
        descriptor["pairing_relay_url"],
        original["pairing_relay_url"]
    );
    data.view
        .relay_information
        .as_object_mut()
        .unwrap()
        .remove("pairing_relay_url");
    let without_pairing = data.view.gateway_information().unwrap();
    assert!(without_pairing.get("pairing_relay_url").is_none());
    assert_eq!(
        without_pairing["enrollment_gateway"]["pairing"],
        "unavailable"
    );
    let no_membership = fixture(false).view.gateway_information().unwrap();
    assert_eq!(no_membership["supported_nips"], json!([1, 11, 42, 98]));
}

#[test]
fn missing_native_membership_and_changed_owners_never_become_provider_grants() {
    let fixture = fixture(true);
    let base = fixture.view.clone();
    let mut changed = base.clone();
    changed.channel_membership = signed(
        &fixture.relay,
        39002,
        tags(&[
            &["d", &base.channel_id],
            &["p", &base.bot_public_key, "", "bot"],
        ]),
        "",
    );
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.channel_membership = signed(
        &fixture.relay,
        39002,
        tags(&[
            &["d", &base.channel_id],
            &["p", &base.intended_public_key, "", "member"],
        ]),
        "",
    );
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.channel_metadata = signed(
        &fixture.relay,
        39000,
        tags(&[&["d", &uuid::Uuid::new_v4().to_string()], &["t", "stream"]]),
        "",
    );
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.channel_metadata = signed(
        &fixture.intended,
        39000,
        tags(&[&["d", &base.channel_id], &["t", "stream"]]),
        "",
    );
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.profiles[1] = signed(
        &fixture.intended,
        0,
        vec![],
        "{\"display_name\":\"enrollment_bot\"}",
    );
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.relay_membership = None;
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.relay_membership = Some(signed(
        &fixture.relay,
        13534,
        tags(&[&["member", &base.bot_public_key, "member"]]),
        "",
    ));
    assert!(changed.validate().is_err());
    changed = base;
    changed.relay_information["self"] = fixture.bot.public_key().to_hex().into();
    assert!(changed.validate().is_err());
}

#[test]
fn optional_native_profiles_do_not_become_channel_admission_or_publication_requirements() {
    let fixture = fixture(true);
    let mut view = fixture.view;
    view.profiles.remove(0);
    view.validate().unwrap();
    view.validate_bot_mention("@enrollment_bot").unwrap();
    assert!(view
        .query(
            &json!([{"kinds":[0],"authors":[view.intended_public_key],"limit":1}]),
            None
        )
        .unwrap()
        .is_empty());
    assert_eq!(
        view.query(&json!([{"kinds":[39000],"#d":[view.channel_id]}]), None)
            .unwrap(),
        vec![view.channel_metadata.clone()]
    );

    // Legacy proof flows do not require either native participant to publish
    // optional kind-0 metadata. Existing signed native membership is sufficient.
    view.profiles.clear();
    view.validate().unwrap();
    assert!(view
        .query(&json!([{"kinds":[0],"limit":50}]), None)
        .unwrap()
        .is_empty());
    assert_eq!(
        view.query(
            &json!([{"kinds":[39002],"#p":[view.intended_public_key]}]),
            None
        )
        .unwrap(),
        vec![view.channel_membership.clone()]
    );
    assert!(
        view.validate_bot_mention("@enrollment_bot").is_err(),
        "the opt-in native mention format still needs the actual bot profile"
    );
}

#[test]
fn native_mention_format_requires_actual_bot_profile_but_never_own_profile() {
    let fixture = fixture(false);
    let mut view = fixture.view;
    view.profiles.pop();
    view.validate().unwrap();
    assert!(view.validate_bot_mention("@enrollment_bot").is_err());
    view.profiles.push(view.profiles[0].clone());
    assert!(
        view.validate().is_err(),
        "duplicate native authors remain denied"
    );
    view.profiles.push(view.profiles[0].clone());
    assert!(
        view.validate().is_err(),
        "optional profile metadata remains bounded"
    );
}

#[test]
fn native_query_matcher_denies_foreign_filters_and_arbitrary_query_extensions() {
    let fixture = fixture(false);
    let view = &fixture.view;
    let foreign = nostr::Keys::generate().public_key().to_hex();
    for filter in [
        json!({"kinds":[39000],"#d":[uuid::Uuid::new_v4().to_string()]}),
        json!({"kinds":[9],"#h":[uuid::Uuid::new_v4().to_string()]}),
        json!({"kinds":[0],"authors":[foreign]}),
        json!({"kinds":[39002],"#p":[foreign]}),
        json!({"kinds":[39002]}),
        json!({"kinds":[1],"limit":500}),
        json!({"kinds":[0],"callback":"https://foreign.invalid"}),
        json!({"kinds":[0],"search":"bot","search_mode":"sql"}),
        json!({"kinds":[39000],"limit":9_007_199_254_740_992u64}),
    ] {
        assert!(view.query(&json!([filter]), None).is_err(), "{filter}");
    }
    assert_eq!(
        view.query(
            &json!([{"kinds":[30622],"#p":[view.intended_public_key],"limit":1}]),
            None
        )
        .unwrap(),
        Vec::<Value>::new()
    );
    assert_eq!(
        view.query(
            &json!([{"kinds":[0],"search":"enroll","search_mode":"prefix","limit":50,"page":1}]),
            None
        )
        .unwrap(),
        vec![view.profiles[1].clone()]
    );
    assert_eq!(
        view.query(&json!([{"kinds":[0],"limit":50,"page":2}]), None)
            .unwrap(),
        Vec::<Value>::new()
    );
}

#[test]
fn native_profile_batch_can_include_real_channel_members_without_fetching_extra_profiles() {
    let fixture = fixture(false);
    let mut view = fixture.view;
    let native_owner = nostr::Keys::generate().public_key().to_hex();
    view.channel_membership = signed(
        &fixture.relay,
        39002,
        tags(&[
            &["d", &view.channel_id],
            &["p", &view.intended_public_key, "", "member"],
            &["p", &view.bot_public_key, "", "bot"],
            &["p", &native_owner, "", "owner"],
        ]),
        "",
    );
    let profiles = view
        .query(
            &json!([{"kinds":[0],"authors":[native_owner,view.intended_public_key,view.bot_public_key],"limit":3}]),
            None,
        )
        .unwrap();
    assert_eq!(profiles.len(), 2);
    for original in &view.profiles {
        assert!(profiles.contains(original));
    }
}

#[test]
fn native_timeline_can_only_project_requesters_original_bot_challenge() {
    let fixture = fixture(false);
    let view = &fixture.view;
    let challenge = signed(
        &fixture.intended,
        9,
        tags(&[&["h", &view.channel_id], &["p", &view.bot_public_key]]),
        "@enrollment_bot exact original challenge",
    );
    let filter = json!([{"kinds":[9,40002,45001,45003],"#h":[view.channel_id],"limit":1}]);
    assert_eq!(view.query(&filter, None).unwrap(), Vec::<Value>::new());
    assert_eq!(
        view.query(&filter, Some(&challenge)).unwrap(),
        vec![challenge.clone()]
    );
    assert_eq!(
        view.query(
            &json!([{"ids":[challenge["id"]],"limit":1}]),
            Some(&challenge)
        )
        .unwrap(),
        vec![challenge.clone()]
    );
    assert_eq!(
        view.query(
            &json!([
                {"kinds":[9],"#h":[view.channel_id]}, {"kinds":[9],"#h":[view.channel_id]},
            ]),
            Some(&challenge)
        )
        .unwrap(),
        vec![challenge]
    );
    let foreign = signed(
        &fixture.bot,
        9,
        tags(&[&["h", &view.channel_id], &["p", &view.bot_public_key]]),
        "another person's message",
    );
    assert!(view.query(&filter, Some(&foreign)).is_err());
}

#[test]
fn bot_mention_uses_actual_effective_native_profile_without_renaming() {
    let fixture = fixture(false);
    fixture
        .view
        .validate_bot_mention("@enrollment_bot")
        .unwrap();
    for value in [
        "enrollment_bot",
        "@ignored_fallback",
        "@Enrollment_Bot",
        "@with spaces",
        "@",
    ] {
        assert!(fixture.view.validate_bot_mention(value).is_err());
    }
    let mut view = fixture.view;
    view.profiles[1] = signed(&fixture.bot, 0, vec![], "{\"name\":\"fallback_bot\"}");
    view.validate_bot_mention("@fallback_bot").unwrap();
    view.profiles[1] = signed(
        &fixture.bot,
        0,
        vec![],
        "{\"display_name\":\"\",\"name\":\"fallback_bot\"}",
    );
    assert!(
        view.validate_bot_mention("@fallback_bot").is_err(),
        "empty native display_name is not a missing field"
    );
}

#[test]
fn native_directory_pagination_keeps_original_event_order_and_identity() {
    let fixture = fixture(false);
    let view = &fixture.view;
    let first = view.query(&json!([{"kinds":[0],"limit":1}]), None).unwrap();
    let next = view.query(&json!([{"kinds":[0],"limit":1,"until":first[0]["created_at"],"before_id":first[0]["id"]}]), None).unwrap();
    assert_eq!(next.len(), 1);
    assert_ne!(first[0]["id"], next[0]["id"]);
    let all = view.query(&json!([{"kinds":[0],"limit":2}]), None).unwrap();
    assert_eq!(all, [first, next].concat());
}

#[test]
fn public_join_policy_preserves_absence_and_rejects_duplicate_or_replaced_fields() {
    assert_eq!(parse_native_join_policy(b"{}").unwrap(), json!({}));
    assert_eq!(
        parse_native_join_policy(b"{\"policy\":null}").unwrap(),
        json!({"policy":null})
    );
    for bytes in [
        br#"{"policy":null,"policy":{"version":"changed","age_attestation_required":false}}"#.as_slice(),
        br#"{"policy":{"version":"one","version":"two","age_attestation_required":true}}"#.as_slice(),
        br#"{"policy":{"version":"one","age_attestation_required":"yes"}}"#.as_slice(),
        br#"{"policy":{"version":"one","age_attestation_required":true,"login_url":"https://foreign.invalid"}}"#.as_slice(),
    ] { assert!(parse_native_join_policy(bytes).is_err()); }
    // Large escaped public Markdown stays supported without increasing the
    // command/authentication parser bound or treating malformed data as absence.
    let document = json!({"policy":{"version":"owner","age_attestation_required":true,"terms_markdown":"\u{0001}".repeat(180_000)}});
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(bytes.len() > llull_buzz_wire::MAX_BYTES);
    assert_eq!(parse_native_join_policy(&bytes).unwrap(), document);
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 65_536);
        bytes.push(socket.read_u8().await.unwrap());
    }
    let header = String::from_utf8(bytes).unwrap();
    let length = header
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length <= llull_buzz_wire::MAX_BYTES);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await.unwrap();
    (header, body)
}

#[tokio::test]
async fn fixed_native_origin_directory_uses_exact_generated_queries_and_real_owner_signatures() {
    for (absent_policy, nip43, profile_count) in [
        (false, true, 2),
        (true, true, 2),
        (false, true, 1),
        (false, true, 0),
        (false, false, 1),
        (false, false, 0),
    ] {
        let mut fixture = fixture(nip43);
        if profile_count == 1 {
            fixture.view.profiles.remove(0);
        }
        if profile_count == 0 {
            fixture.view.profiles.clear();
        }
        let original = fixture.view.clone();
        let response_view = fixture.view.clone();
        let service = nostr::Keys::generate();
        let service_key = service.public_key().to_hex();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut seen_requests = BTreeSet::new();
            let mut query_response = vec![
                response_view.channel_metadata.clone(),
                response_view.channel_membership.clone(),
            ];
            query_response.extend(response_view.profiles.iter().cloned());
            if let Some(membership) = &response_view.relay_membership {
                query_response.push(membership.clone());
            }
            for (path, status, response) in [
                ("/info", "200 OK", response_view.relay_information.clone()),
                ("/query", "200 OK", Value::Array(query_response)),
                (
                    "/api/join-policy",
                    if absent_policy {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    },
                    if absent_policy {
                        json!({"error":"not-found"})
                    } else {
                        response_view.join_policy.unwrap()
                    },
                ),
                ("/moderation/restricted", "200 OK", json!([])),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, body) = read_request(&mut socket).await;
                let method = if path == "/query" { "POST" } else { "GET" };
                assert!(headers.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
                assert!(headers
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("host: native-owner.synthetic.invalid")));
                if path == "/query" {
                    let query: Value = parse(&body).unwrap();
                    let mut expected = vec![
                        json!({"kinds":[39000],"authors":[response_view.relay_public_key],"#d":[response_view.channel_id],"limit":1}),
                        json!({"kinds":[39002],"authors":[response_view.relay_public_key],"#d":[response_view.channel_id],"limit":1}),
                        json!({"kinds":[0],"authors":[response_view.intended_public_key],"limit":1}),
                        json!({"kinds":[0],"authors":[response_view.bot_public_key],"limit":1}),
                    ];
                    if nip43 {
                        expected.push(json!({"kinds":[13534],"authors":[response_view.relay_public_key],"limit":1}));
                    }
                    assert_eq!(query, Value::Array(expected));
                } else {
                    assert!(body.is_empty());
                }
                if matches!(path, "/query" | "/moderation/restricted") {
                    let credential = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                                .map(|(_, value)| value.trim())
                        })
                        .unwrap();
                    let native = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        credential.strip_prefix("Nostr ").unwrap(),
                    )
                    .unwrap();
                    let text = std::str::from_utf8(&native).unwrap();
                    let verified = buzz_auth::verify_nip98_event(
                        text,
                        &format!("https://native-owner.synthetic.invalid{path}"),
                        method,
                        Some(&body),
                    )
                    .unwrap();
                    assert_eq!(
                        verified.to_hex(),
                        service_key,
                        "only the existing service transport signs the source read"
                    );
                    let event = native::event(&native).unwrap();
                    assert_eq!(
                        native::tag(&event, "payload").unwrap(),
                        llull_buzz_wire::sha256(&body)
                    );
                    assert!(!native::tag(&event, "nonce").unwrap().is_empty());
                    assert!(
                        seen_requests.insert(event.id.to_hex()),
                        "native owner replay guard cannot accept a duplicate request"
                    );
                }
                let response = serde_json::to_vec(&response).unwrap();
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).as_bytes()).await.unwrap();
                socket.write_all(&response).await.unwrap();
            }
        });
        let (credential, source) = tracked_native_source(
            &original.community_id,
            &origin,
            "https://native-owner.synthetic.invalid",
            &service,
            fixture.relay.public_key(),
        );
        let view = source
            .enrollment_directory(
                &original.community_id,
                &original.channel_id,
                &original.intended_public_key,
                &original.bot_public_key,
            )
            .await
            .unwrap();
        assert_eq!(view.channel_metadata, original.channel_metadata);
        assert_eq!(view.channel_membership, original.channel_membership);
        assert_eq!(view.profiles, original.profiles);
        assert_eq!(view.relay_information, original.relay_information);
        assert_eq!(
            view.join_policy,
            if absent_policy {
                None
            } else {
                original.join_policy
            }
        );
        task.await.unwrap();
        assert_eq!(
            view.admission_check.intended_public_key,
            original.intended_public_key
        );
        assert_eq!(
            view.admission_check.response_sha256,
            llull_buzz_wire::sha256(b"[]")
        );
        drop(source);
        drop(credential);
    }
}

#[tokio::test]
async fn fixed_native_origin_directory_never_follows_public_document_redirects() {
    let fixture = fixture(false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (headers, _) = read_request(&mut socket).await;
        assert!(headers.starts_with("GET /info HTTP/1.1"));
        socket.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://foreign.invalid/info\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let (credential, source) = tracked_native_source(
        &fixture.view.community_id,
        &origin,
        "https://native-owner.synthetic.invalid",
        &nostr::Keys::generate(),
        fixture.relay.public_key(),
    );
    assert!(source
        .enrollment_directory(
            &fixture.view.community_id,
            &fixture.view.channel_id,
            &fixture.view.intended_public_key,
            &fixture.view.bot_public_key
        )
        .await
        .is_err());
    task.await.unwrap();
    drop(source);
    drop(credential);
}

fn native_restriction(
    pubkey: &str,
    actor: &str,
    banned: bool,
    muted_until: Option<DateTime<Utc>>,
) -> Value {
    json!({"pubkey":pubkey,"banned":banned,"ban_expires_at":null,"ban_reason":if banned {Some("synthetic private ban reason")} else {None},"muted_until":muted_until,"mute_reason":if muted_until.is_some() {Some("synthetic private timeout reason")} else {None},"actor_pubkey":actor,"updated_at":Utc::now()})
}

#[test]
fn native_restriction_observation_requires_complete_typed_rows_and_denies_ban_or_timeout() {
    let intended = nostr::Keys::generate().public_key().to_hex();
    let actor = nostr::Keys::generate().public_key().to_hex();
    let other = nostr::Keys::generate().public_key().to_hex();
    admit_native_restrictions(b"[]", &intended).unwrap();
    let banned = native_restriction(&intended, &actor, true, None);
    let timed_out = native_restriction(
        &intended,
        &actor,
        false,
        Some(Utc::now() + ChronoDuration::minutes(1)),
    );
    assert!(admit_native_restrictions(&canonical(&json!([banned])).unwrap(), &intended).is_err());
    assert!(
        admit_native_restrictions(&canonical(&json!([timed_out])).unwrap(), &intended).is_err()
    );
    admit_native_restrictions(
        &canonical(&json!([native_restriction(&other, &actor, true, None)])).unwrap(),
        &intended,
    )
    .unwrap();
    let mut missing = native_restriction(&other, &actor, true, None);
    missing.as_object_mut().unwrap().remove("ban_expires_at");
    let mut extra = native_restriction(&other, &actor, true, None);
    extra["next_cursor"] = json!("unproved-page");
    let mut malformed = native_restriction(&other, &actor, true, None);
    malformed["updated_at"] = json!("unknown-time");
    for value in [
        json!({"items":[],"next_cursor":null}),
        json!([missing]),
        json!([extra]),
        json!([malformed]),
        json!([native_restriction(&other, "not-a-key", true, None)]),
        json!([
            native_restriction(&other, &actor, true, None),
            native_restriction(&other, &actor, true, None)
        ]),
    ] {
        assert!(
            admit_native_restrictions(&serde_json::to_vec(&value).unwrap(), &intended).is_err()
        );
    }
    assert!(
        admit_native_restrictions(br#"[{"pubkey":"same","pubkey":"changed"}]"#, &intended).is_err()
    );
}

#[test]
fn native_admission_check_is_target_bound_fresh_and_never_a_membership_grant() {
    let base = fixture(false).view;
    base.validate().unwrap();
    let mut changed = base.clone();
    changed.admission_check.intended_public_key = nostr::Keys::generate().public_key().to_hex();
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.admission_check.community_id = "another-community".into();
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.admission_check.valid_until = Utc::now() - ChronoDuration::seconds(1);
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.admission_check.checked_at = Utc::now() + ChronoDuration::seconds(1);
    assert!(changed.validate().is_err());
    changed = base.clone();
    changed.admission_check.valid_until =
        changed.admission_check.checked_at + ChronoDuration::seconds(31);
    assert!(changed.validate().is_err());
    changed = base;
    changed
        .admission_check
        .moderation_endpoint
        .push_str("?limit=1");
    assert!(changed.validate().is_err());
}

#[tokio::test]
async fn tracked_native_moderation_read_is_exact_and_fails_closed() {
    let intended = nostr::Keys::generate().public_key().to_hex();
    let moderator = nostr::Keys::generate();
    let other = nostr::Keys::generate().public_key().to_hex();
    let ban = native_restriction(&intended, &moderator.public_key().to_hex(), true, None);
    let timeout = native_restriction(
        &intended,
        &moderator.public_key().to_hex(),
        false,
        Some(Utc::now() + ChronoDuration::minutes(1)),
    );
    let cases = vec![
        ("200 OK", canonical(&json!([])).unwrap(), "", true),
        (
            "200 OK",
            canonical(&json!([native_restriction(
                &other,
                &moderator.public_key().to_hex(),
                true,
                None
            )]))
            .unwrap(),
            "",
            true,
        ),
        ("200 OK", canonical(&json!([ban])).unwrap(), "", false),
        ("200 OK", canonical(&json!([timeout])).unwrap(), "", false),
        (
            "403 Forbidden",
            br#"{"error":"moderator access required"}"#.to_vec(),
            "",
            false,
        ),
        ("503 Service Unavailable", b"[]".to_vec(), "", false),
        (
            "307 Temporary Redirect",
            b"[]".to_vec(),
            "Location: https://foreign.invalid/moderation/restricted\r\n",
            false,
        ),
        (
            "206 Partial Content",
            b"[]".to_vec(),
            "Content-Range: rows 0-0/2\r\n",
            false,
        ),
        (
            "200 OK",
            b"[]".to_vec(),
            "Link: </moderation/restricted?page=2>; rel=next\r\n",
            false,
        ),
        (
            "200 OK",
            br#"{"items":[],"next_cursor":"unproved"}"#.to_vec(),
            "",
            false,
        ),
        ("200 OK", b"[".to_vec(), "", false),
        (
            "200 OK",
            vec![b' '; llull_buzz_wire::MAX_BYTES + 1],
            "",
            false,
        ),
    ];
    for (status, response, extra, allowed) in cases {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let expected_key = moderator.public_key().to_hex();
        let expected_digest = llull_buzz_wire::sha256(&response);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_request(&mut socket).await;
            assert!(headers.starts_with("GET /moderation/restricted HTTP/1.1\r\n"));
            assert!(body.is_empty());
            assert!(headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("host: native-owner.synthetic.invalid")));
            let authorization = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .map(|(_, value)| value.trim())
                })
                .unwrap();
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                authorization.strip_prefix("Nostr ").unwrap(),
            )
            .unwrap();
            let request = native::event(&bytes).unwrap();
            assert_eq!(
                native::tag(&request, "payload").unwrap(),
                llull_buzz_wire::sha256(b"")
            );
            assert!(!native::tag(&request, "nonce").unwrap().is_empty());
            let verified = buzz_auth::verify_nip98_event(
                std::str::from_utf8(&bytes).unwrap(),
                "https://native-owner.synthetic.invalid/moderation/restricted",
                "GET",
                Some(b""),
            )
            .unwrap();
            assert_eq!(verified.to_hex(), expected_key);
            socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",response.len()).as_bytes()).await.unwrap();
            let _ = socket.write_all(&response).await;
        });
        let (credential, source) = tracked_native_source(
            "synthetic-moderation-community",
            &origin,
            "https://native-owner.synthetic.invalid",
            &moderator,
            nostr::Keys::generate().public_key(),
        );
        let result = source.enrollment_admission_check(&intended).await;
        assert_eq!(result.is_ok(), allowed, "{status}");
        if let Ok(check) = result {
            check
                .validate("synthetic-moderation-community", &intended, Utc::now())
                .unwrap();
            assert_eq!(check.response_sha256, expected_digest);
            let exposed = serde_json::to_string(&check).unwrap();
            assert!(!exposed.contains("private ban reason"));
            assert!(!exposed.contains("ban_reason"));
            assert!(!exposed.contains(&other));
        }
        server.await.unwrap();
        drop(source);
        drop(credential);
    }
}

#[test]
fn native_moderation_signer_requires_exact_tracked_capability_key_and_binding() {
    let key = nostr::Keys::generate();
    let relay = nostr::Keys::generate().public_key();
    let origin = "http://127.0.0.1:18443";
    let public = "https://native-owner.synthetic.invalid";
    let plain =
        HttpNativeOrigin::new("community".into(), origin, public, key.clone(), relay).unwrap();
    assert!(!plain.enrollment_directory_enabled());
    assert!(
        plain
            .with_enrollment_admission_signer(key.clone().into())
            .is_err(),
        "legacy signer cannot impersonate admission capability"
    );
    let (credential, source) = tracked_native_source("community", origin, public, &key, relay);
    assert!(source.enrollment_directory_enabled());
    let broad =
        HttpNativeOrigin::new("community".into(), origin, public, key.clone(), relay).unwrap();
    assert!(broad
        .with_enrollment_admission_signer(credential.credential.signer("native-http").unwrap())
        .is_err());
    let wrong_origin = HttpNativeOrigin::new(
        "community".into(),
        "http://127.0.0.1:18444",
        public,
        key.clone(),
        relay,
    )
    .unwrap();
    assert!(wrong_origin
        .with_enrollment_admission_signer(
            credential
                .credential
                .signer("native-enrollment-admission")
                .unwrap()
        )
        .is_err());
    let wrong_key = HttpNativeOrigin::new(
        "community".into(),
        origin,
        public,
        nostr::Keys::generate(),
        relay,
    )
    .unwrap();
    assert!(wrong_key
        .with_enrollment_admission_signer(
            credential
                .credential
                .signer("native-enrollment-admission")
                .unwrap()
        )
        .is_err());
    drop(source);
    drop(credential);
}
