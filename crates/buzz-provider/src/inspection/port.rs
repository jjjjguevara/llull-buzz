//! Standalone fixed local private port; no HTTP route, replay admission or daemon.
use super::{acquire, authority, catalog, clock, deny, files, history, json, relations, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// JWT base64url expansion is itself bounded. SQL's 700,000-byte opaque FETCH
// chunks are independently re-framed into smaller signed-file transport chunks;
// this is not a smaller accepted row/data ceiling or a change to public wire.
const RESPONSE_CHUNK_BYTES: usize = 500_000;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    kind: String,
    relation: String,
    snapshot: String,
    request_sha256: String,
    index: u64,
    pages: u64,
    stream_bytes: u64,
    stream_sha256: String,
    raw_sha256: String,
    payload_base64url: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationReceipt {
    relation: String,
    rows: u64,
    raw_bytes: u64,
    largest_row: u64,
    snapshot: String,
    framed_bytes: u64,
    framed_sha256: String,
    pages: Vec<String>,
    eof: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    kind: String,
    status: String,
    installation: String,
    source_revision: String,
    implementation_sha256: String,
    generation: u64,
    profile_sha256: String,
    request_sha256: String,
    operation_ref: String,
    operation_sha256: String,
    configuration_sha256: String,
    configuration_generation: u64,
    source_copy_sha256: String,
    target_copy_sha256: String,
    controller: String,
    run: String,
    recovery_epoch: u64,
    challenge: String,
    basis_ref: String,
    basis_sha256: String,
    database_oid: u32,
    inspector_oid: u32,
    view_owner_oid: u32,
    catalog_sha256: String,
    schema_manifest_sha256: String,
    snapshot: String,
    relations: Vec<RelationReceipt>,
    unresolved: Vec<String>,
}
/// Only the filename is returned. Original metadata and credentials are never
/// printed to stdout; an authorized operator reads the held-mode private files.
pub struct LocalReceipt {
    pub filename: String,
}
struct Inputs {
    trust: files::PrivateBytes,
    profile: files::PrivateBytes,
    request: files::PrivateBytes,
    signer: files::PrivateBytes,
    password: files::PrivateBytes,
    certificate: files::PrivateBytes,
    schema: files::PrivateBytes,
}
impl Inputs {
    fn read(directory: &files::PrivateDirectory, budget: &mut clock::Budget) -> Result<Self> {
        Ok(Self {
            trust: directory.read("trust.json", budget)?,
            profile: directory.read("profile.jws", budget)?,
            request: directory.read("request.jws", budget)?,
            signer: directory.read("response-key.pem", budget)?,
            password: directory.read("sql-password", budget)?,
            certificate: directory.read("sql-root.pem", budget)?,
            schema: directory.read("schema-manifest.json", budget)?,
        })
    }
    fn current(
        &self,
        directory: &files::PrivateDirectory,
        budget: &mut clock::Budget,
    ) -> Result<()> {
        for (name, bytes) in [
            ("trust.json", self.trust.bytes()),
            ("profile.jws", self.profile.bytes()),
            ("request.jws", self.request.bytes()),
            ("response-key.pem", self.signer.bytes()),
            ("sql-password", self.password.bytes()),
            ("sql-root.pem", self.certificate.bytes()),
            ("schema-manifest.json", self.schema.bytes()),
        ] {
            let digest = llull_buzz_wire::sha256(bytes);
            directory.current(name, &digest, budget)?;
        }
        budget.sample(clock::now())?;
        Ok(())
    }
}
async fn signed_file<T: Serialize + serde::de::DeserializeOwned>(
    body: T,
    auth: &authority::Authenticated,
    inputs: &Inputs,
    directory: &files::PrivateDirectory,
    outputs: &mut Vec<files::Output>,
    budget: &mut clock::Budget,
) -> Result<String> {
    tokio::task::yield_now().await;
    let observed = budget.sample(clock::now())?;
    let body_value = serde_json::to_value(&body).map_err(|_| deny("response_body"))?;
    let body_sha256 = llull_buzz_wire::sha256(
        &serde_json::to_vec(&body_value).map_err(|_| deny("response_body"))?,
    );
    let signed = auth.sign(body, inputs.signer.bytes(), observed, auth.expires())?;
    auth.current(budget.sample(clock::now())?)?;
    if signed.len() > acquire::ENVELOPE_BYTES {
        return Err(unknown("inspection_response_envelope"));
    }
    let filename = format!("{}.jws", llull_buzz_wire::sha256(&signed));
    let mut output = directory.write_response(&filename, &signed, budget)?;
    output.body_sha256 = body_sha256;
    let digest_matches = output.sha256 == filename[..64];
    outputs.push(output);
    #[cfg(test)]
    tests::source_point("after-page-write", directory, budget);
    if !digest_matches {
        return Err(unknown("inspection_output_digest"));
    }
    tokio::task::yield_now().await;
    verify_output(
        outputs
            .last()
            .ok_or_else(|| deny("inspection_output_missing"))?,
        auth,
        directory,
        budget,
    )?;
    auth.current(budget.sample(clock::now())?)?;
    Ok(filename)
}
fn verify_output(
    output: &files::Output,
    auth: &authority::Authenticated,
    directory: &files::PrivateDirectory,
    budget: &mut clock::Budget,
) -> Result<()> {
    let raw = directory.read_response(output, budget)?;
    auth.verify_response(
        raw.bytes(),
        &output.body_sha256,
        budget.sample(clock::now())?,
    )?;
    drop(raw);
    auth.current(budget.sample(clock::now())?)?;
    Ok(())
}
fn unknown(code: &'static str) -> super::InspectionError {
    super::InspectionError::Unknown {
        code,
        first: None,
        cleanup: Vec::new(),
    }
}
fn receipt_body(
    auth: &authority::Authenticated,
    session: &catalog::Session,
    catalog_sha256: String,
    relation_receipts: Vec<RelationReceipt>,
    mut unresolved: Vec<String>,
) -> Receipt {
    unresolved.extend(super::UNRESOLVED.map(str::to_owned));
    unresolved.sort();
    unresolved.dedup();
    let request = auth.request();
    let db = &auth.profile().database;
    Receipt {
        kind: "llull-buzz-private-metadata-receipt/v1".into(),
        status: "PARTIAL".into(),
        installation: auth.profile().installation.clone(),
        source_revision: auth.source_revision().into(),
        implementation_sha256: auth.profile().implementation_sha256.clone(),
        generation: auth.generation(),
        profile_sha256: auth.profile_hash().into(),
        request_sha256: auth.request_hash().into(),
        operation_ref: request.operation_ref.clone(),
        operation_sha256: request.operation_sha256.clone(),
        configuration_sha256: request.configuration_sha256.clone(),
        configuration_generation: request.configuration_generation,
        source_copy_sha256: request.source_copy_sha256.clone(),
        target_copy_sha256: request.target_copy_sha256.clone(),
        controller: request.controller.clone(),
        run: request.run.clone(),
        recovery_epoch: request.recovery_epoch,
        challenge: request.challenge.clone(),
        basis_ref: request.basis_ref.clone(),
        basis_sha256: request.basis_sha256.clone(),
        database_oid: db.database_oid,
        inspector_oid: db.inspector_oid,
        view_owner_oid: db.view_owner_oid,
        catalog_sha256,
        schema_manifest_sha256: db.schema_manifest_sha256.clone(),
        snapshot: session.snapshot.clone(),
        relations: relation_receipts,
        unresolved,
    }
}
async fn retain(
    raw: &BTreeMap<String, Vec<Vec<u8>>>,
    facts: &BTreeMap<String, acquire::Preflight>,
    auth: &authority::Authenticated,
    inputs: &Inputs,
    directory: &files::PrivateDirectory,
    outputs: &mut Vec<files::Output>,
    budget: &mut clock::Budget,
) -> Result<Vec<RelationReceipt>> {
    acquire::complete_preflight(facts.iter().map(|(name, f)| (name.as_str(), f)))?;
    let mut receipts = Vec::new();
    for relation in relations::RELATIONS {
        let rows = raw
            .get(relation.name)
            .ok_or_else(|| deny("inventory_retained_scope"))?;
        let fact = &facts[relation.name];
        let mut stream = Vec::new();
        let mut total = 0u64;
        let mut largest = 0u64;
        for bytes in rows {
            json::validate_raw(bytes)?;
            stream.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            stream.extend_from_slice(bytes);
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| unknown("inventory_retained_counter"))?;
            largest = largest.max(bytes.len() as u64);
            budget.sample(clock::now())?;
        }
        if rows.len() as u64 != fact.count || total != fact.bytes || largest != fact.largest {
            return Err(unknown("inventory_retained_totals"));
        }
        let digest = llull_buzz_wire::sha256(&stream);
        let pages = stream.len().div_ceil(RESPONSE_CHUNK_BYTES);
        let mut filenames = Vec::new();
        for (index, bytes) in stream.chunks(RESPONSE_CHUNK_BYTES).enumerate() {
            let body = Page {
                kind: "llull-buzz-private-metadata-page/v1".into(),
                relation: relation.name.into(),
                snapshot: fact.snapshot.clone(),
                request_sha256: auth.request_hash().into(),
                index: index as u64,
                pages: pages as u64,
                stream_bytes: stream.len() as u64,
                stream_sha256: digest.clone(),
                raw_sha256: llull_buzz_wire::sha256(bytes),
                payload_base64url: URL_SAFE_NO_PAD.encode(bytes),
            };
            filenames.push(signed_file(body, auth, inputs, directory, outputs, budget).await?);
        }
        receipts.push(RelationReceipt {
            relation: relation.name.into(),
            rows: fact.count,
            raw_bytes: fact.bytes,
            largest_row: fact.largest,
            snapshot: fact.snapshot.clone(),
            framed_bytes: stream.len() as u64,
            framed_sha256: digest,
            pages: filenames,
            eof: true,
        });
        budget.sample(clock::now())?;
    }
    if raw.len() != relations::RELATIONS.len() {
        return Err(deny("inventory_retained_scope"));
    }
    Ok(receipts)
}
async fn observe(
    sql: &mut acquire::NativeSession,
    auth: &authority::Authenticated,
    manifest: &catalog::SchemaManifest,
    budget: &mut clock::Budget,
) -> Result<(
    catalog::Session,
    BTreeMap<String, acquire::Preflight>,
    BTreeMap<String, Vec<Vec<u8>>>,
    String,
    Vec<String>,
)> {
    let session: catalog::Session =
        json::decode(sql.scalar(catalog::SESSION_SQL, budget).await?.as_bytes())?;
    session.verify(&auth.profile().database)?;
    // Every fixed metadata relation and every privilege catalog gets a genuine
    // scalar preflight before any payload/catalog body is transferred.
    let facts = sql.inventory_preflights(budget).await?;
    let catalog_facts = sql.catalog_preflights(budget).await?;
    if facts
        .values()
        .chain(catalog_facts.values())
        .any(|f| f.snapshot != session.snapshot)
    {
        return Err(unknown("inspection_snapshot"));
    }
    let catalogs = sql.collect_catalog(&catalog_facts, budget).await?;
    let catalog_digest = catalog::verify_retained(&catalogs, auth, manifest, budget)?;
    let raw = sql.collect_inventory(&facts, budget).await?;
    let gaps =
        history::verify_complete(&raw, auth.profile(), auth.request().recovery_epoch, budget)?;
    sql.check_snapshot(&session.snapshot, budget).await?;
    Ok((session, facts, raw, catalog_digest, gaps))
}
/// The shared cancellation future is polled before owned work, at every live
/// budget boundary, and alongside native awaits. It stays latched through SQL
/// cleanup and publication; cleanup itself always attempts each owned resource.
pub async fn run_local(
    cancel: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<LocalReceipt> {
    let mut budget = clock::Budget::new(clock::now(), i64::MAX)?;
    budget.watch(cancel.boxed().shared());
    budget.sample(clock::now())?;
    let directory = files::PrivateDirectory::open(&mut budget)?;
    run_owned(directory, budget).await
}
// There is no production transport/profile/path factory. Source controls enter
// with their owned final file transport and cfg(test)-only final SQL transport.
async fn run_owned(
    directory: files::PrivateDirectory,
    mut budget: clock::Budget,
) -> Result<LocalReceipt> {
    let mut outputs = Vec::new();
    let first = async {
        tokio::task::yield_now().await;
        let inputs = Inputs::read(&directory, &mut budget)?;
        let auth = authority::Authenticated::admit(
            inputs.trust.bytes(),
            inputs.profile.bytes(),
            inputs.request.bytes(),
            &mut budget,
            clock::now(),
        )?;
        if llull_buzz_wire::sha256(inputs.schema.bytes())
            != auth.profile().database.schema_manifest_sha256
        {
            return Err(deny("inspection_schema_bytes"));
        }
        let manifest: catalog::SchemaManifest = json::decode(inputs.schema.bytes())?;
        manifest.authenticate(&auth, &mut budget)?;
        budget.constrain(manifest.expiry())?;
        #[cfg(test)]
        tests::source_point("before-connect", &directory, &mut budget);
        let mut sql = acquire::NativeSession::connect(
            &auth,
            inputs.password.bytes(),
            inputs.certificate.bytes(),
            &mut budget,
        )
        .await?;
        let observed = observe(&mut sql, &auth, &manifest, &mut budget).await;
        #[cfg(test)]
        tests::source_point("after-observe", &directory, &mut budget);
        let (session, facts, raw, catalog_digest, gaps) = sql.finish(observed, &mut budget).await?;
        tokio::task::yield_now().await;
        #[cfg(test)]
        tests::source_point("after-sql-cleanup", &directory, &mut budget);
        inputs.current(&directory, &mut budget)?;
        manifest.current(&auth, budget.sample(clock::now())?)?;
        let receipts = retain(
            &raw,
            &facts,
            &auth,
            &inputs,
            &directory,
            &mut outputs,
            &mut budget,
        )
        .await?;
        let body = receipt_body(&auth, &session, catalog_digest, receipts, gaps);
        let filename =
            signed_file(body, &auth, &inputs, &directory, &mut outputs, &mut budget).await?;
        inputs.current(&directory, &mut budget)?;
        #[cfg(test)]
        tests::source_point("before-final-output-check", &directory, &mut budget);
        for output in &outputs {
            tokio::task::yield_now().await;
            verify_output(output, &auth, &directory, &mut budget)?;
        }
        #[cfg(test)]
        tests::source_point("after-final-output-check", &directory, &mut budget);
        let terminal = budget.sample(clock::now())?;
        auth.current(terminal)?;
        manifest.current(&auth, terminal)?;
        Ok(LocalReceipt { filename })
    }
    .await;
    finish_files(first, directory, outputs, &mut budget)
}

fn finish_files(
    mut first: Result<LocalReceipt>,
    directory: files::PrivateDirectory,
    outputs: Vec<files::Output>,
    budget: &mut clock::Budget,
) -> Result<LocalReceipt> {
    let mut faults = Vec::new();
    let anchor = directory.cleanup_anchor();
    if let Err(error) = budget.sample(clock::now()) {
        if first.is_ok() {
            first = Err(error);
        }
    }
    if first.is_ok() {
        for output in &outputs {
            if let Err(error) = directory.check_response_generation(output) {
                first = Err(error);
                break;
            }
        }
    }
    let initially_successful = first.is_ok();
    if first.is_err() {
        for output in &outputs {
            if directory.remove_output(output).is_err() {
                faults.push("inspection_output_remove");
            }
        }
    }
    faults.extend(directory.close());
    // Nothing hashes/decodes/constructs a receipt after this final live sample.
    if let Err(error) = budget.sample(clock::now()) {
        if first.is_ok() {
            first = Err(error);
        }
    }
    if initially_successful && (first.is_err() || !faults.is_empty()) && !outputs.is_empty() {
        // A terminal close/clock failure may occur after the original directory
        // was consumed. Reopen only the fixed protected directory, remove only
        // retained exact inode identities, and never turn cleanup into success.
        match files::PrivateDirectory::open_for_cleanup(&anchor) {
            Ok(reopened) => {
                for output in &outputs {
                    if reopened.remove_output(output).is_err() {
                        faults.push("inspection_output_remove");
                    }
                }
                faults.extend(reopened.close());
            }
            Err(_) => faults.push("inspection_output_directory_reopen"),
        }
    }
    if !faults.is_empty() {
        return Err(super::InspectionError::Unknown {
            code: "inspection_owned_cleanup",
            first: first.err().map(Box::new),
            cleanup: faults,
        });
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    struct OwnedFixture {
        path: std::path::PathBuf,
        dev: u64,
        inode: u64,
    }
    impl Drop for OwnedFixture {
        fn drop(&mut self) {
            let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
                return;
            };
            if !metadata.is_dir() || metadata.dev() != self.dev || metadata.ino() != self.inode {
                return;
            }
            if let Ok(entries) = std::fs::read_dir(&self.path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let selected = [
                        "trust.json",
                        "profile.jws",
                        "request.jws",
                        "response-key.pem",
                        "sql-password",
                        "sql-root.pem",
                        "schema-manifest.json",
                    ]
                    .contains(&name);
                    let output = name.len() == 68
                        && name.ends_with(".jws")
                        && llull_buzz_wire::hash(&name[..64]).is_ok();
                    if selected || output {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn actual_private_port_retention_genuine_crypto_and_nofollow_files_preserve_201_1000() {
        // Final SQL transport is INERT here: exact raw row/chunk custody has
        // separate actual ChunkLedger controls. Crypto, raw parser, protected
        // file I/O, page/receipt retention and terminal cleanup are active.
        for count in [1u64, 201, 1000] {
            let (trust, profile, request, signer, start) = authority::synthetic_port_inputs();
            let fixture = std::env::current_dir()
                .unwrap()
                .join(format!("buzz-inspection-port-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&fixture).unwrap();
            let metadata = std::fs::symlink_metadata(&fixture).unwrap();
            let owned = OwnedFixture {
                path: fixture.clone(),
                dev: metadata.dev(),
                inode: metadata.ino(),
            };
            std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
            for (name, bytes) in [
                ("trust.json", trust.as_slice()),
                ("profile.jws", profile.as_slice()),
                ("request.jws", request.as_slice()),
                ("response-key.pem", signer.as_slice()),
                ("sql-password", b"synthetic-test-only".as_slice()),
                ("sql-root.pem", b"synthetic-not-a-TLS-fixture".as_slice()),
                ("schema-manifest.json", b"{}".as_slice()),
            ] {
                let path = fixture.join(name);
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let mut budget = clock::Budget::new(start, i64::MAX).unwrap();
            let directory =
                files::PrivateDirectory::open_synthetic_fixture(&fixture, &mut budget).unwrap();
            let inputs = Inputs::read(&directory, &mut budget).unwrap();
            let auth = authority::Authenticated::admit(
                inputs.trust.bytes(),
                inputs.profile.bytes(),
                inputs.request.bytes(),
                &mut budget,
                clock::now(),
            )
            .unwrap();
            let mut raw = relations::RELATIONS
                .iter()
                .map(|r| (r.name.into(), Vec::new()))
                .collect::<BTreeMap<String, Vec<Vec<u8>>>>();
            for index in 0..count {
                let bytes=serde_json::to_vec(&serde_json::json!({"relation":"resource_replays","row_sha256":"a".repeat(64),"row_key":["synthetic-scope",format!("{index:064x}")],"metadata":{"scope":"synthetic-scope","event_id":format!("{index:064x}"),"expires_at":"2026-10-07T00:00:00+00:00"}})).unwrap();
                history::Row::parse(&bytes, "resource_replays").unwrap();
                raw.get_mut("resource_replays").unwrap().push(bytes);
            }
            let facts = raw
                .iter()
                .map(|(name, rows)| {
                    (
                        name.clone(),
                        acquire::Preflight {
                            count: rows.len() as u64,
                            bytes: rows.iter().map(|r| r.len() as u64).sum(),
                            largest: rows.iter().map(|r| r.len() as u64).max().unwrap_or(0),
                            snapshot: "1:2:".into(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut outputs = Vec::new();
            let receipts = retain(
                &raw,
                &facts,
                &auth,
                &inputs,
                &directory,
                &mut outputs,
                &mut budget,
            )
            .await
            .unwrap();
            let selected = receipts
                .iter()
                .find(|r| r.relation == "resource_replays")
                .unwrap();
            assert_eq!(selected.rows, count);
            assert!(selected.eof);
            let mut framed = Vec::new();
            for bytes in &raw["resource_replays"] {
                framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                framed.extend_from_slice(bytes);
            }
            assert_eq!(selected.framed_sha256, llull_buzz_wire::sha256(&framed));
            for filename in &selected.pages {
                let signed = std::fs::read(fixture.join(filename)).unwrap();
                assert_eq!(
                    filename,
                    &format!("{}.jws", llull_buzz_wire::sha256(&signed))
                );
                let encoded = std::str::from_utf8(&signed)
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap();
                let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
                let claims: authority::Signed<Page> = llull_buzz_wire::parse(&decoded).unwrap();
                assert_eq!(claims.body.request_sha256, auth.request_hash());
                assert_eq!(claims.body.stream_sha256, selected.framed_sha256);
                // The actual signer already verified each JWS under the pinned
                // response key before write. Here exact original raw transport
                // bytes and their independent digest are inspected afterward.
                let chunk = URL_SAFE_NO_PAD
                    .decode(&claims.body.payload_base64url)
                    .unwrap();
                assert_eq!(claims.body.raw_sha256, llull_buzz_wire::sha256(&chunk));
            }
            inputs.current(&directory, &mut budget).unwrap();
            let anchor = directory.cleanup_anchor();
            for output in &outputs {
                directory.remove_output(output).unwrap();
            }
            assert!(directory.close().is_empty());
            drop(inputs);
            // No operator keys/fixture files survive the owned source control.
            for name in [
                "trust.json",
                "profile.jws",
                "request.jws",
                "response-key.pem",
                "sql-password",
                "sql-root.pem",
                "schema-manifest.json",
            ] {
                std::fs::remove_file(fixture.join(name)).unwrap();
            }
            std::fs::remove_dir(&fixture).unwrap();
            assert!(!fixture.exists());
            let _ = anchor;
            drop(owned);
        }
    }

    // AUTHORED UNRUN. All private keys/identities/SQL rows below are synthetic.
    // Only the final SQL socket is INERT; actual fixed SQL generation, scalar
    // aggregate preflight, chunk ledger, catalog and history validators, genuine
    // ES256, private persisted files and terminal owner logic are exercised.
    type RawRows = BTreeMap<String, Vec<Vec<u8>>>;
    fn row(relation: &str, key: serde_json::Value, metadata: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"relation":relation,"row_sha256":"a".repeat(64),"row_key":key,"metadata":metadata})).unwrap()
    }
    fn put(
        rows: &mut RawRows,
        relation: &str,
        key: serde_json::Value,
        metadata: serde_json::Value,
    ) {
        rows.get_mut(relation)
            .unwrap()
            .push(row(relation, key, metadata));
    }
    fn complete_rows(count: usize) -> RawRows {
        let mut rows = relations::RELATIONS
            .iter()
            .map(|r| (r.name.into(), Vec::new()))
            .collect::<RawRows>();
        put(
            &mut rows,
            "provider_control",
            serde_json::json!([1]),
            serde_json::json!({"singleton":1,"recovery_epoch":1,"activation":"foundation-only"}),
        );
        for index in 0..count {
            let consumer = if count == 1 {
                "consumer-a".into()
            } else {
                format!("consumer-{index:04}")
            };
            let metadata = serde_json::json!({"consumer_id":consumer,"revision":1,"policy_revision":"policy-a","authority_epoch":1,
                "community_id":"community-a","service_principal":"principal-a","service_public_key":"a".repeat(64),
                "enrollment_bot_key":"b".repeat(64),"enrollment_channel":"channel-a","modules":{"module-a":{
                    "actions":["read"],"principal_issuers":["fixture.invalid"],"context_domains":["context-a"],"task_schemas":["task-a"],"tools":{}}}});
            put(
                &mut rows,
                "consumer_registry",
                serde_json::json!([consumer]),
                serde_json::json!({"consumer_id":consumer,"revision":1,
                "registration_sha256":"a".repeat(64),"active":true,"registration_metadata":metadata,"registration_shape_valid":true,
                "modules_shape_valid":true,"original_registration_sha256":"c".repeat(64)}),
            );
            put(
                &mut rows,
                "registration_history",
                serde_json::json!([consumer, 1]),
                serde_json::json!({"consumer_id":consumer,"revision":1,
                "active":true,"recorded_at":"2026-10-07T00:00:00Z","registration_metadata":metadata,"registration_shape_valid":true,
                "modules_shape_valid":true,"original_registration_sha256":"c".repeat(64)}),
            );
        }
        rows
    }
    fn with_history(mut rows: RawRows, empty: bool) -> RawRows {
        let id = "00000000-0000-0000-0000-000000000001";
        put(
            &mut rows,
            "observation_snapshots",
            serde_json::json!([id]),
            serde_json::json!({"snapshot_id":id,"consumer_id":"consumer-a",
            "module_id":"module-a","context_domain":"context-a","recovery_epoch":1,"high_water":if empty {0} else {3},
            "created_at":"2026-10-07T00:00:00Z","expires_at":"2026-10-08T00:00:00Z"}),
        );
        if empty {
            return rows;
        }
        put(
            &mut rows,
            "observation_counters",
            serde_json::json!(["consumer-a"]),
            serde_json::json!({"consumer_id":"consumer-a","next_sequence":3,"retained_after":0}),
        );
        for sequence in 1..=3 {
            let record = serde_json::json!({"sequence":sequence,"operation":"read","operation_id":format!("operation-{sequence}"),
                "execution":"completed","revision":1,"resource":{"namespace":"consumer-a","ref":format!("resource-{sequence}"),"revision":"1"}});
            let digest = format!("{sequence:064x}");
            put(
                &mut rows,
                "observations",
                serde_json::json!(["consumer-a", sequence]),
                serde_json::json!({"consumer_id":"consumer-a","sequence":sequence,
                "module_id":"module-a","context_domain":"context-a","recorded_at":"2026-10-07T00:00:00Z",
                "record_metadata":record,"record_shape_valid":true,"original_record_sha256":digest}),
            );
            put(
                &mut rows,
                "observation_snapshot_entries",
                serde_json::json!([id, sequence]),
                serde_json::json!({"snapshot_id":id,"ordinal":sequence,
                "record_metadata":record,"record_shape_valid":true,"original_record_sha256":digest}),
            );
        }
        for revision in 1..=3 {
            let record = serde_json::json!({"enrollment_id":"enrollment-a","consumer_id":"consumer-a","module_id":"module-a","issuer":"fixture.invalid",
                "subject":"synthetic-user","native_key":"d".repeat(64),"revision":revision,"authority_epoch":revision+7,
                "active":revision!=2,"key_retired":false,"proof_event_id":"e".repeat(64),"created_at":"2026-10-07T00:00:00Z"});
            put(
                &mut rows,
                "enrollment_history",
                serde_json::json!(["enrollment-a", revision]),
                serde_json::json!({"enrollment_id":"enrollment-a","revision":revision,
                "action":match revision {1=>"intended-key-proven",2=>"access-revoked",_=>"access-restored"},"recorded_at":"2026-10-07T00:00:00Z",
                "record_metadata":record,"record_shape_valid":true,"original_record_sha256":format!("{revision:064x}")}),
            );
            if revision == 3 {
                let mut current = record;
                current["original_proof_event_sha256"] = serde_json::json!("f".repeat(64));
                put(
                    &mut rows,
                    "enrollments",
                    serde_json::json!(["enrollment-a"]),
                    current,
                );
            }
        }
        rows
    }
    fn mutate(
        rows: &mut RawRows,
        relation: &str,
        index: usize,
        update: impl FnOnce(&mut serde_json::Value),
    ) {
        let mut value: serde_json::Value = serde_json::from_slice(&rows[relation][index]).unwrap();
        update(&mut value);
        rows.get_mut(relation).unwrap()[index] = serde_json::to_vec(&value).unwrap();
    }
    struct CompleteFixture {
        owned: OwnedFixture,
        sql: Option<acquire::InertSql>,
        now: i64,
        flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
        log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }
    impl CompleteFixture {
        fn new(count: usize, rows: RawRows, bad_migrations: bool) -> Self {
            let database = authority::synthetic_database();
            let catalogs = catalog::synthetic_catalog(&database);
            let mut migrations = relations::migration_pins();
            if bad_migrations {
                *migrations.values_mut().next().unwrap() = "0".repeat(64);
            }
            let now = clock::now();
            let schema = serde_json::to_vec(&serde_json::json!({"v":1,"source_revision":"b244ba7560112e498ee6d68a48d035c99cb0b8c2","generation":1,
                "database_oid":database.database_oid,"migration_sha256":migrations,"catalog_sha256":catalog::synthetic_catalog_digest(&catalogs),
                "observed_us":now,"expires_us":now+30_000_000})).unwrap();
            let certificate = b"INERT synthetic TLS socket certificate; no native TLS claim";
            let (trust, profile, request, signer, now) =
                authority::synthetic_complete_inputs(count, &schema, certificate);
            let path = std::env::current_dir()
                .unwrap()
                .join(format!("buzz-complete-source-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let owned = OwnedFixture {
                path,
                dev: metadata.dev(),
                inode: metadata.ino(),
            };
            for (name, bytes) in [
                ("trust.json", trust.as_slice()),
                ("profile.jws", profile.as_slice()),
                ("request.jws", request.as_slice()),
                ("response-key.pem", signer.as_slice()),
                ("sql-password", b"synthetic-only".as_slice()),
                ("sql-root.pem", certificate.as_slice()),
                ("schema-manifest.json", schema.as_slice()),
            ] {
                std::fs::write(owned.path.join(name), bytes).unwrap();
                std::fs::set_permissions(
                    owned.path.join(name),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            let session = serde_json::json!({"current_user":authority::INSPECTOR,"session_user":authority::INSPECTOR,"database":database.database,
                "database_oid":database.database_oid,"address":database.server_address,"port":database.port,"version":database.server_version_num,
                "search_path":catalog::INSPECTION_SEARCH_PATH,"read_only":"on","isolation":"repeatable read","temporary":false,"create":false,"snapshot":"1:2:"}).to_string();
            let sql = acquire::InertSql::new(session, rows, catalogs);
            let log = sql.log.clone();
            Self {
                owned,
                sql: Some(sql),
                now,
                flag: Default::default(),
                log,
            }
        }
        fn point(&self, phase: &'static str, action: &'static str) {
            SOURCE_POINT.with(|slot| {
                *slot.borrow_mut() =
                    Some((phase, action, self.owned.path.clone(), self.flag.clone()))
            });
        }
        async fn run(&mut self) -> Result<LocalReceipt> {
            let flag = self.flag.clone();
            let mut budget = clock::Budget::new(self.now, self.now + 30_000_000).unwrap();
            budget.watch(
                futures_util::future::poll_fn(move |_| {
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .boxed()
                .shared(),
            );
            let directory =
                files::PrivateDirectory::open_synthetic_fixture(&self.owned.path, &mut budget)?;
            let mut sql = self.sql.take().unwrap();
            sql.cancellation = Some(self.flag.clone());
            sql.install();
            let result = run_owned(directory, budget).await;
            acquire::InertSql::clear();
            files::set_test_fault("");
            SOURCE_POINT.with(|slot| {
                slot.borrow_mut().take();
            });
            result
        }
        fn output_names(&self) -> Vec<std::path::PathBuf> {
            std::fs::read_dir(&self.owned.path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap().to_string_lossy().len() == 68)
                .collect()
        }
    }
    impl Drop for CompleteFixture {
        fn drop(&mut self) {
            acquire::InertSql::clear();
            files::set_test_fault("");
            SOURCE_POINT.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    type Point = (
        &'static str,
        &'static str,
        std::path::PathBuf,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    );
    thread_local! { static SOURCE_POINT: std::cell::RefCell<Option<Point>> = const { std::cell::RefCell::new(None) }; }
    pub(super) fn source_point(
        phase: &str,
        _directory: &files::PrivateDirectory,
        budget: &mut clock::Budget,
    ) {
        let selected = SOURCE_POINT.with(|slot| {
            if slot.borrow().as_ref().is_some_and(|point| point.0 == phase) {
                slot.borrow_mut().take()
            } else {
                None
            }
        });
        let Some((_, action, path, flag)) = selected else {
            return;
        };
        match action {
            "cancel" => flag.store(true, std::sync::atomic::Ordering::SeqCst),
            "backward" => {
                let _ = budget.sample(0);
            }
            "expired" => {
                let _ = budget.constrain(clock::now());
            }
            "output-read" | "output-close" | "output-owner" | "final-hash-clock" => {
                files::set_test_fault(action)
            }
            "remove-failure" => {
                files::set_test_fault("remove");
                let _ = budget.sample(0);
            }
            "same-size" | "delete" | "replace" | "mode" => {
                let output = std::fs::read_dir(&path)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.file_name().unwrap().to_string_lossy().len() == 68)
                    .unwrap();
                match action {
                    "same-size" => {
                        let mut bytes = std::fs::read(&output).unwrap();
                        bytes[0] ^= 1;
                        std::fs::write(&output, bytes).unwrap();
                    }
                    "delete" => std::fs::remove_file(&output).unwrap(),
                    "replace" => {
                        let original = std::fs::File::open(&output).unwrap();
                        std::fs::remove_file(&output).unwrap();
                        std::fs::write(&output, b"synthetic foreign replacement").unwrap();
                        drop(original);
                    }
                    "mode" => {
                        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644))
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
            }
            field => {
                let request = std::fs::read(path.join("request.jws")).unwrap();
                let changed = authority::synthetic_changed_request(&request, field);
                std::fs::write(path.join("request.jws"), changed).unwrap();
            }
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_actual_catalog_history_crypto_and_custody_1_201_1000_zero_work() {
        for count in [0usize, 1, 201, 1000] {
            let mut fixture = CompleteFixture::new(count, complete_rows(count), false);
            let receipt = fixture.run().await.unwrap();
            assert!(fixture.owned.path.join(&receipt.filename).is_file());
            let signed = std::fs::read(fixture.owned.path.join(&receipt.filename)).unwrap();
            let encoded = std::str::from_utf8(&signed)
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap();
            let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
            let receipt: authority::Signed<Receipt> = llull_buzz_wire::parse(&decoded).unwrap();
            assert_eq!(receipt.body.status, "PARTIAL");
            assert_eq!(receipt.body.relations.len(), 27);
            assert_eq!(
                receipt
                    .body
                    .relations
                    .iter()
                    .find(|r| r.relation == "consumer_registry")
                    .unwrap()
                    .rows,
                count as u64
            );
            assert_eq!(
                receipt
                    .body
                    .relations
                    .iter()
                    .find(|r| r.relation == "registration_history")
                    .unwrap()
                    .rows,
                count as u64
            );
            assert!(receipt.body.relations.iter().all(|r| r.eof));
            assert!(super::super::UNRESOLVED.iter().all(|gap| receipt
                .body
                .unresolved
                .iter()
                .any(|v| v == gap)));
            assert!(fixture.log.borrow().iter().any(|v| v == "execute:ROLLBACK"));
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        }
        let mut empty = CompleteFixture::new(1, with_history(complete_rows(1), true), false);
        empty.run().await.unwrap();
        let mut history = CompleteFixture::new(1, with_history(complete_rows(1), false), false);
        history.run().await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_authenticates_migration_pins_before_sql_or_output() {
        let mut fixture = CompleteFixture::new(1, complete_rows(1), true);
        assert!(fixture.run().await.is_err());
        assert!(fixture.log.borrow().is_empty());
        assert!(fixture.output_names().is_empty());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_history_refuses_holes_tail_duplicates_types_and_accepts_named_uncertainty() {
        for fault in [
            "missing-first",
            "missing-interior",
            "later-than-current",
            "epoch",
            "identity",
            "snapshot-tail",
            "snapshot-all",
            "duplicate",
            "malformed",
            "empty-positive",
        ] {
            let mut rows = with_history(complete_rows(1), fault == "empty-positive");
            match fault {
                "missing-first" => {
                    rows.get_mut("enrollment_history").unwrap().remove(0);
                }
                "missing-interior" => {
                    rows.get_mut("enrollment_history").unwrap().remove(1);
                }
                "later-than-current" => mutate(&mut rows, "enrollments", 0, |v| {
                    v["metadata"]["revision"] = serde_json::json!(2);
                    v["metadata"]["authority_epoch"] = serde_json::json!(9);
                    v["metadata"]["active"] = serde_json::json!(false);
                }),
                "epoch" => mutate(&mut rows, "enrollment_history", 1, |v| {
                    v["metadata"]["record_metadata"]["authority_epoch"] = serde_json::json!(90)
                }),
                "identity" => mutate(&mut rows, "enrollment_history", 1, |v| {
                    v["metadata"]["record_metadata"]["native_key"] =
                        serde_json::json!("0".repeat(64))
                }),
                "snapshot-tail" => {
                    rows.get_mut("observation_snapshot_entries").unwrap().pop();
                }
                "snapshot-all" => rows
                    .get_mut("observation_snapshot_entries")
                    .unwrap()
                    .clear(),
                "duplicate" => {
                    let duplicate = rows["enrollment_history"][0].clone();
                    rows.get_mut("enrollment_history").unwrap().push(duplicate);
                }
                "malformed" => mutate(&mut rows, "enrollment_history", 0, |v| {
                    v["metadata"]["record_metadata"]["revision"] = serde_json::json!("unknown")
                }),
                "empty-positive" => mutate(&mut rows, "observation_snapshots", 0, |v| {
                    v["metadata"]["high_water"] = serde_json::json!(1)
                }),
                _ => unreachable!(),
            }
            let mut fixture = CompleteFixture::new(1, rows, false);
            assert!(fixture.run().await.is_err(), "{fault}");
            assert!(fixture.output_names().is_empty());
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        }
        let mut rows = with_history(complete_rows(1), false);
        rows.get_mut("observations").unwrap().remove(0);
        mutate(&mut rows, "observation_counters", 0, |v| {
            v["metadata"]["retained_after"] = serde_json::json!(1)
        });
        let mut fixture = CompleteFixture::new(1, rows, false);
        let result = fixture.run().await.unwrap();
        let bytes = std::fs::read(fixture.owned.path.join(result.filename)).unwrap();
        let payload = URL_SAFE_NO_PAD
            .decode(
                std::str::from_utf8(&bytes)
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap();
        let signed: authority::Signed<Receipt> = llull_buzz_wire::parse(&payload).unwrap();
        assert!(signed
            .body
            .unresolved
            .iter()
            .any(|v| v == "inventory-snapshot-original-completeness-unproven"));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_changed_original_request_generation_and_bindings_refuse() {
        for field in [
            "subject",
            "source",
            "generation",
            "epoch",
            "config",
            "source-copy",
            "target-copy",
            "challenge",
            "operation",
        ] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.point("after-observe", field);
            assert!(fixture.run().await.is_err(), "{field}");
            assert!(fixture.output_names().is_empty());
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_final_sql_payload_and_cleanup_failures_keep_unknown_and_no_receipt() {
        for fault in [
            "oversize",
            "fetch",
            "early-eof",
            "chunk-digest",
            "chunk-order",
            "cursor-close",
            "rollback",
            "connection-close",
        ] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.sql.as_mut().unwrap().fault = fault;
            let result = fixture.run().await;
            assert!(result.is_err(), "{fault}");
            assert!(fixture.output_names().is_empty());
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
            if fault == "oversize" {
                assert!(!fixture.log.borrow().iter().any(|v| v == "fetch"));
            }
            if ["cursor-close", "rollback", "connection-close"].contains(&fault) {
                assert!(matches!(
                    result,
                    Err(super::super::InspectionError::Unknown { .. })
                ));
            }
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_cancel_at_connection_observation_cleanup_retention_and_terminal_refuses()
    {
        for phase in [
            "before-connect",
            "after-observe",
            "after-sql-cleanup",
            "after-page-write",
            "before-final-output-check",
            "after-final-output-check",
        ] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.point(phase, "cancel");
            assert!(fixture.run().await.is_err(), "{phase}");
            assert!(fixture.output_names().is_empty());
        }
        for fault in ["cancel-connect", "cancel-cleanup"] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.sql.as_mut().unwrap().fault = fault;
            assert!(fixture.run().await.is_err());
            assert!(fixture.output_names().is_empty());
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        }
        let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
        fixture
            .flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(fixture.run().await.is_err());
        assert!(fixture.output_names().is_empty());
        assert!(fixture.log.borrow().is_empty());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_persisted_bytes_identity_modes_terminal_clock_and_cleanup_refuse() {
        for action in [
            "same-size",
            "delete",
            "replace",
            "mode",
            "output-read",
            "output-close",
            "output-owner",
            "final-hash-clock",
            "remove-failure",
            "backward",
            "expired",
        ] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.point("after-page-write", action);
            let result = fixture.run().await;
            assert!(result.is_err(), "{action}");
            if ["delete", "replace", "remove-failure"].contains(&action) {
                assert!(matches!(
                    result,
                    Err(super::super::InspectionError::Unknown { .. })
                ));
            }
            if !["replace", "remove-failure"].contains(&action) {
                assert!(fixture.output_names().is_empty(), "{action}");
            }
            if action == "replace" {
                assert_eq!(
                    std::fs::read(&fixture.output_names()[0]).unwrap(),
                    b"synthetic foreign replacement"
                );
            }
        }
        for action in [
            "same-size",
            "delete",
            "mode",
            "output-read",
            "output-close",
            "backward",
            "expired",
        ] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            fixture.point("before-final-output-check", action);
            assert!(fixture.run().await.is_err(), "terminal {action}");
        }
        let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
        fixture.point("after-final-output-check", "expired");
        assert!(fixture.run().await.is_err());
        assert!(fixture.output_names().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_initial_claim_scope_and_private_sentinel_adverses_refuse() {
        for field in ["subject", "source", "generation"] {
            let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
            let path = fixture.owned.path.join("request.jws");
            let before = std::fs::read(&path).unwrap();
            std::fs::write(path, authority::synthetic_changed_request(&before, field)).unwrap();
            assert!(fixture.run().await.is_err(), "{field}");
            assert!(fixture.log.borrow().is_empty());
            assert!(fixture.output_names().is_empty());
        }
        for fault in [
            "missing-member",
            "unknown-member",
            "duplicate-member",
            "missing-registration-history",
            "private-sentinel",
        ] {
            let mut rows = complete_rows(1);
            match fault {
                "missing-member" => rows.get_mut("consumer_registry").unwrap().clear(),
                "unknown-member" => mutate(&mut rows, "consumer_registry", 0, |v| {
                    v["metadata"]["consumer_id"] = serde_json::json!("unknown");
                    v["row_key"] = serde_json::json!(["unknown"]);
                }),
                "duplicate-member" => {
                    let duplicate = rows["consumer_registry"][0].clone();
                    rows.get_mut("consumer_registry").unwrap().push(duplicate);
                }
                "missing-registration-history" => {
                    rows.get_mut("registration_history").unwrap().clear()
                }
                "private-sentinel" => mutate(&mut rows, "consumer_registry", 0, |v| {
                    v["metadata"]["private_body"] =
                        serde_json::json!("DO_NOT_EXPORT_PRIVATE_SENTINEL")
                }),
                _ => unreachable!(),
            }
            let mut fixture = CompleteFixture::new(1, rows, false);
            assert!(fixture.run().await.is_err(), "{fault}");
            assert!(fixture.output_names().is_empty());
            assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_port_primary_failure_and_late_cancellation_survive_cleanup_unknown() {
        let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
        fixture.sql.as_mut().unwrap().fault = "fetch";
        fixture.sql.as_mut().unwrap().cleanup_fault = "rollback";
        let result = fixture.run().await;
        match result {
            Err(super::super::InspectionError::Unknown {
                code,
                first,
                cleanup,
            }) => {
                assert_eq!(code, "inspection_sql_cleanup");
                assert!(cleanup.contains(&"inspection_rollback"));
                assert!(matches!(
                    first.as_deref(),
                    Some(super::super::InspectionError::Unknown {
                        code: "inert_fetch",
                        ..
                    })
                ));
            }
            _ => panic!("primary fetch refusal and rollback UNKNOWN were not retained"),
        }
        assert!(fixture.output_names().is_empty());
        assert_eq!(fixture.log.borrow().last().unwrap(), "close");
        let mut fixture = CompleteFixture::new(1, complete_rows(1), false);
        fixture.sql.as_mut().unwrap().fault = "cancel-cleanup";
        fixture.sql.as_mut().unwrap().cleanup_fault = "connection-close";
        match fixture.run().await {
            Err(super::super::InspectionError::Unknown {
                code,
                first,
                cleanup,
            }) => {
                assert_eq!(code, "inspection_sql_cleanup");
                assert!(cleanup.contains(&"inspection_connection_close"));
                assert!(matches!(
                    first.as_deref(),
                    Some(super::super::InspectionError::Unknown {
                        code: "inspection_cancelled",
                        ..
                    })
                ));
            }
            _ => panic!("late cancellation and connection UNKNOWN were not retained"),
        }
        assert!(fixture.output_names().is_empty());
    }
}
