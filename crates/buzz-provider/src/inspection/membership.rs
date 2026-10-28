//! Current native relay membership, distinct from provider enrollment retirement.
//! This is an opt-in read-only observation, never a revocation or live gate probe.
use super::{acquire, authority::Authenticated, clock::Budget, deny, json, receiver, Result};
use crate::native_custody::ProcessIncarnation;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const INSPECTOR: &str = "buzz_native_recovery_inspector";
pub const SOURCES: &[&str] = &[
    "native_members",
    "native_database",
    "native_inheritance",
    "native_settings",
    "native_collations",
    "native_key_collations",
    "native_roles",
    "native_memberships",
    "native_relations",
    "native_columns",
    "native_schemas",
    "native_functions",
    "native_sequences",
    "native_indexes",
    "native_constraints",
    "native_triggers",
    "native_policies",
];
/// Membership can route to a bounded-stale reader in this revision. This initial
/// observation admits only an absent/blank READ_DATABASE_URL and hence writer.
pub const POLICY_FILES: [(&str, &str); 6] = [
    (
        "crates/buzz-relay/src/api/mod.rs",
        "402b3440b221211def6e5a7acda4a7ffd37267187635abf03500160c228f4471",
    ),
    (
        "crates/buzz-relay/src/config.rs",
        "4f7b4612d2bb3052e2284cc77ef0c2766bd5fc2bf778ab014f8b191ce6022564",
    ),
    (
        "crates/buzz-relay/src/main.rs",
        "58a284c4e518eae5c3ef72f29e72f15584bb356af334975a740b51f3b1cb166c",
    ),
    (
        "crates/buzz-db/src/store/relay_members.rs",
        "62a7196b01dac655ccaaf950edc08f009fe00f84582ade39662e95c7cca5f5be",
    ),
    (
        "crates/buzz-db/src/runtime/mod.rs",
        "94164b0e2344217b92d42c9b4cabea9aa83af3e104d04b6eee958de10c40baec",
    ),
    (
        "migrations/0001_initial_schema.sql",
        "6acb496695f650e49c7e44404894899a04fc971d8c2c4f7862bd62797c23799d",
    ),
];
pub(crate) fn source(name: &str) -> Option<&'static str> {
    if !SOURCES.contains(&name) {
        return None;
    }
    match name {
        "native_members" => Some("SELECT to_jsonb(r)::text AS raw FROM public.relay_members r ORDER BY community_id,pubkey COLLATE \"C\""),
        "native_database" => Some("SELECT json_build_object('oid',d.oid,'name',d.datname,'owner',d.datdba,'acl',d.datacl::text,'create',has_database_privilege(current_user,d.oid,'CREATE'),'temporary',has_database_privilege(current_user,d.oid,'TEMPORARY'))::text AS raw FROM pg_catalog.pg_database d WHERE d.datname=current_database()"),
        "native_inheritance" => Some("SELECT json_build_object('child',inhrelid,'parent',inhparent)::text AS raw FROM pg_catalog.pg_inherits ORDER BY inhrelid,inhparent"),
        "native_settings" => Some("SELECT json_build_object('database',setdatabase,'role',setrole,'config',setconfig)::text AS raw FROM pg_catalog.pg_db_role_setting ORDER BY setdatabase,setrole"),
        "native_collations" => Some("SELECT json_build_object('oid',c.oid,'schema',n.nspname,'name',c.collname,'deterministic',c.collisdeterministic,'provider',c.collprovider::text,'encoding',c.collencoding,'version',c.collversion,'actual_version',pg_collation_actual_version(c.oid),'catalog',to_jsonb(c))::text AS raw FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE c.oid IN (SELECT a.attcollation FROM pg_catalog.pg_attribute a WHERE a.attrelid='public.relay_members'::regclass AND a.attnum>0 AND NOT a.attisdropped UNION SELECT unnest(i.indcollation) FROM pg_catalog.pg_index i WHERE i.indrelid='public.relay_members'::regclass) ORDER BY c.oid"),
        "native_key_collations" => Some("SELECT json_build_object('index',i.indexrelid,'relation',i.indrelid,'primary',i.indisprimary,'collations',ARRAY(SELECT x.collation_oid FROM unnest(i.indcollation) WITH ORDINALITY x(collation_oid,ord) ORDER BY x.ord))::text AS raw FROM pg_catalog.pg_index i WHERE i.indrelid='public.relay_members'::regclass ORDER BY i.indexrelid"),
        _ => super::catalog::QUERIES.iter().find(|q| Some(q.name) == name.strip_prefix("native_")).map(|q| q.sql),
    }
}
pub(crate) const SESSION_SQL: &str = "WITH header AS MATERIALIZED (SELECT json_build_object('current_user',current_user,'session_user',session_user,'inspector_oid',(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user),'database',current_database(),'database_oid',(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),'address',inet_server_addr()::text,'port',inet_server_port(),'version',current_setting('server_version_num')::integer,'system_identifier',(SELECT system_identifier::text FROM pg_catalog.pg_control_system()),'postmaster_started',pg_postmaster_start_time()::text,'backend_pid',pg_backend_pid(),'in_recovery',pg_is_in_recovery(),'ssl',(SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()),'search_path',current_setting('search_path'),'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),'create',has_database_privilege(current_user,current_database(),'CREATE'),'temporary',has_database_privilege(current_user,current_database(),'TEMPORARY'),'snapshot',pg_current_snapshot()::text)::text AS raw) SELECT CASE WHEN octet_length(raw)<=8192 THEN raw ELSE '{\"refused\":\"native_session_scalar_bound\"}' END FROM header";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeDatabase {
    pub host: String,
    pub port: u16,
    pub database: String,
    /// Runtime application's role, explicitly distinct from the inspection role.
    pub runtime_role: String,
    pub database_oid: u32,
    pub inspector_oid: u32,
    pub server_address: String,
    pub server_version_num: i32,
    pub system_identifier: String,
    pub ssl_root_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_sha256: Option<String>,
    pub relay_members_oid: u32,
    pub relay_members_owner_oid: u32,
    pub catalog_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MembershipProfile {
    pub kind: String,
    pub receiver_id: String,
    pub process_environment_sha256: String,
    pub database_url_sha256: String,
    pub database: NativeDatabase,
}
impl MembershipProfile {
    pub(crate) fn authenticate(&self, receivers: &receiver::ReceiverProfile) -> Result<()> {
        let d = &self.database;
        if self.kind != "llull-buzz-native-membership-profile/v1"
            || receivers.membership.as_ref() != Some(self)
            || receivers
                .receivers
                .iter()
                .filter(|r| r.receiver_id == self.receiver_id)
                .count()
                != 1
            || d.host.is_empty()
            || d.host.len() > 255
            || d.host.starts_with('/')
            || d.host.chars().any(|c| c.is_whitespace() || c.is_control())
            || d.port == 0
            || d.database.is_empty()
            || d.database.len() > 63
            || d.runtime_role.is_empty()
            || d.runtime_role.len() > 63
            || d.runtime_role == INSPECTOR
            || d.server_address.parse::<std::net::IpAddr>().is_err()
            || [
                d.database_oid,
                d.inspector_oid,
                d.relay_members_oid,
                d.relay_members_owner_oid,
            ]
            .contains(&0)
            || d.inspector_oid == d.relay_members_owner_oid
            || d.system_identifier
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .is_none()
            || d.server_version_num < 150000
        {
            return Err(deny("native_membership_profile"));
        }
        for digest in [
            &self.process_environment_sha256,
            &self.database_url_sha256,
            &d.ssl_root_sha256,
            &d.catalog_sha256,
        ] {
            llull_buzz_wire::hash(digest).map_err(|_| deny("native_membership_profile"))?;
        }
        if let Some(digest) = &d.client_certificate_sha256 {
            llull_buzz_wire::hash(digest).map_err(|_| deny("native_membership_profile"))?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub process: ProcessIncarnation,
    pub process_environment_sha256: String,
    pub database_url_sha256: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub runtime_role: String,
    pub require_relay_membership: bool,
    pub allow_nip_oa_auth: bool,
    pub read_replica: bool,
    pub membership_policy_files: Vec<receiver::MeasuredFile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSession {
    pub current_user: String,
    pub session_user: String,
    pub inspector_oid: u32,
    pub database: String,
    pub database_oid: u32,
    pub address: String,
    pub port: u16,
    pub version: i32,
    pub system_identifier: String,
    pub postmaster_started: String,
    pub backend_pid: u32,
    pub in_recovery: bool,
    pub ssl: bool,
    pub search_path: String,
    pub read_only: String,
    pub isolation: String,
    pub create: bool,
    pub temporary: bool,
    pub snapshot: String,
}
impl NativeSession {
    fn verify(&self, d: &NativeDatabase) -> Result<()> {
        if self.current_user != INSPECTOR
            || self.session_user != INSPECTOR
            || self.inspector_oid != d.inspector_oid
            || self.database != d.database
            || self.database_oid != d.database_oid
            || self.address != d.server_address
            || self.port != d.port
            || self.version != d.server_version_num
            || self.system_identifier != d.system_identifier
            || self.postmaster_started.is_empty()
            || self.backend_pid == 0
            || self.in_recovery
            || !self.ssl
            || self.search_path != "pg_catalog, public"
            || self.read_only != "on"
            || self.isolation != "repeatable read"
            || self.create
            || self.temporary
            || self.snapshot.is_empty()
            || self.snapshot.len() > 4096
        {
            return Err(deny("native_membership_session"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayMember {
    pub community_id: String,
    pub pubkey: String,
    pub role: String,
    pub added_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMembership {
    pub custody_id: String,
    pub community_id: String,
    pub public_key: String,
    pub present: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipObservation {
    pub kind: String,
    pub receiver_id: String,
    pub request_sha256: String,
    pub challenge: String,
    pub observed_us: i64,
    pub acquisition_started_us: i64,
    pub snapshot_observed_us: i64,
    pub source_image_admission_sha256: String,
    pub status: String,
    pub runtime: RuntimeBinding,
    pub session: NativeSession,
    pub catalog_sha256: String,
    pub relay_members_oid: u32,
    pub relay_members_owner_oid: u32,
    pub rows: u64,
    pub raw_bytes: u64,
    pub largest_row: u64,
    pub framed_sha256: String,
    pub eof: bool,
    /// Complete original UTF-8 SQL JSON rows as strings. Their exact bytes can
    /// replay raw totals and length-prefixed digest across JWS normalization.
    pub relay_members: Vec<String>,
    pub original_keys: Vec<KeyMembership>,
    pub unresolved: Vec<String>,
}

fn environment(
    raw: &[u8],
    p: &MembershipProfile,
    process: &ProcessIncarnation,
) -> Result<RuntimeBinding> {
    if raw.is_empty()
        || raw.len() > 1024 * 1024
        || raw.last() != Some(&0)
        || llull_buzz_wire::sha256(raw) != p.process_environment_sha256
    {
        return Err(deny("native_membership_environment"));
    }
    let mut selected = BTreeMap::new();
    for item in raw.split(|c| *c == 0).filter(|v| !v.is_empty()) {
        let Some(pos) = item.iter().position(|c| *c == b'=') else {
            return Err(deny("native_membership_environment"));
        };
        let (key, value) = (&item[..pos], &item[pos + 1..]);
        if key.starts_with(b"PG") {
            return Err(deny("native_membership_ambient_pg_options"));
        }
        if [
            b"DATABASE_URL".as_slice(),
            b"READ_DATABASE_URL",
            b"BUZZ_REQUIRE_RELAY_MEMBERSHIP",
            b"BUZZ_ALLOW_NIP_OA_AUTH",
        ]
        .contains(&key)
            && selected.insert(key, value).is_some()
        {
            return Err(deny("native_membership_environment_duplicate"));
        }
    }
    let text = |key: &[u8]| -> Result<Option<&str>> {
        selected
            .get(key)
            .map(|v| std::str::from_utf8(v).map_err(|_| deny("native_membership_environment")))
            .transpose()
    };
    let enabled = |v: Option<&str>| matches!(v, Some("true" | "1"));
    let required = enabled(text(b"BUZZ_REQUIRE_RELAY_MEMBERSHIP")?);
    let oa = text(b"BUZZ_ALLOW_NIP_OA_AUTH")?;
    let replica = text(b"READ_DATABASE_URL")?.is_some_and(|s| !s.trim().is_empty());
    // Admission is intentionally stricter than upstream's false-on-typo parser.
    if !required || !matches!(oa, None | Some("false" | "0")) || replica {
        return Err(deny("native_membership_gate_configuration"));
    }
    let raw_url = text(b"DATABASE_URL")?.ok_or_else(|| deny("native_membership_database_url"))?;
    let url = url::Url::parse(raw_url).map_err(|_| deny("native_membership_database_url"))?;
    let d = &p.database;
    // Reject libpq query overrides, service/default/socket/multi-host forms.
    // Secrets never leave this parser, its public binding or an error message.
    let mut query_keys = BTreeSet::new();
    for (key, _) in url.query_pairs() {
        if !matches!(
            key.as_ref(),
            "sslmode"
                | "sslrootcert"
                | "sslcert"
                | "sslkey"
                | "connect_timeout"
                | "application_name"
        ) || !query_keys.insert(key.into_owned())
        {
            return Err(deny("native_membership_database_url"));
        }
    }
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.fragment().is_some()
        || url.host_str() != Some(d.host.as_str())
        || url.port().unwrap_or(5432) != d.port
        || url.path() != format!("/{}", d.database)
        || url.username() != d.runtime_role
        || llull_buzz_wire::sha256(raw_url.as_bytes()) != p.database_url_sha256
    {
        return Err(deny("native_membership_database_url"));
    }
    Ok(RuntimeBinding {
        process: process.clone(),
        process_environment_sha256: p.process_environment_sha256.clone(),
        database_url_sha256: p.database_url_sha256.clone(),
        host: d.host.clone(),
        port: d.port,
        database: d.database.clone(),
        runtime_role: d.runtime_role.clone(),
        require_relay_membership: true,
        allow_nip_oa_auth: false,
        read_replica: false,
        membership_policy_files: Vec::new(),
    })
}
fn binding(
    p: &MembershipProfile,
    selection: &receiver::ReceiverSelection,
    observed: &receiver::ReceiverObservation,
    budget: &mut Budget,
) -> Result<RuntimeBinding> {
    budget.sample(super::clock::now())?;
    let clock = observed
        .clock_domain
        .as_ref()
        .ok_or_else(|| deny("native_membership_receiver_unknown"))?;
    let executable = observed
        .executable
        .as_ref()
        .ok_or_else(|| deny("native_membership_receiver_unknown"))?;
    if observed.status != "SOURCE_AND_PROGRAM_OBSERVED_BUILD_UNVERIFIED"
        || clock.receiver != selection.process
        || ProcessIncarnation::read(selection.process.pid)? != selection.process
    {
        return Err(deny("native_membership_receiver_changed"));
    }
    receiver::verify_executable(selection.process.pid, executable, budget)?;
    for measured in &observed.policy_files {
        if receiver::measure(
            Path::new("/"),
            measured.path.trim_start_matches('/'),
            1024 * 1024,
            budget,
        )? != *measured
        {
            return Err(deny("native_membership_receiver_source_changed"));
        }
    }
    // /proc environ is a deliberate kernel pseudo-file. Incarnation and exact
    // executable are checked before and after; only its digest is retained.
    let mut raw = crate::native_custody::bounded_read(
        Path::new(&format!("/proc/{}/environ", selection.process.pid)),
        1024 * 1024,
    )?;
    let result = environment(&raw, p, &selection.process);
    raw.fill(0);
    let mut result = result?;
    result.process = selection.process.clone();
    for (path, hash) in POLICY_FILES {
        let path = format!("{}/{path}", selection.source_root.trim_end_matches('/'));
        let measured = receiver::measure(
            Path::new("/"),
            path.trim_start_matches('/'),
            1024 * 1024,
            budget,
        )?;
        if measured.sha256 != hash {
            return Err(deny("native_membership_source_policy"));
        }
        result.membership_policy_files.push(measured);
    }
    if ProcessIncarnation::read(selection.process.pid)? != selection.process {
        return Err(deny("native_membership_receiver_changed"));
    }
    receiver::verify_executable(selection.process.pid, executable, budget)?;
    budget.sample(super::clock::now())?;
    Ok(result)
}

fn row_bool(row: &serde_json::Value, key: &str) -> Result<bool> {
    row.get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| deny("native_membership_catalog_shape"))
}
fn row_u64(row: &serde_json::Value, key: &str) -> Result<u64> {
    row.get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| deny("native_membership_catalog_shape"))
}
fn row_text<'a>(row: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    row.get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| deny("native_membership_catalog_shape"))
}
pub(super) fn verify_catalog(
    raw: &BTreeMap<String, Vec<Vec<u8>>>,
    p: &MembershipProfile,
    budget: &mut Budget,
) -> Result<String> {
    if raw.len() != SOURCES.len() || SOURCES.iter().any(|name| !raw.contains_key(*name)) {
        return Err(deny("native_membership_catalog_scope"));
    }
    let d = &p.database;
    let mut catalog = BTreeMap::new();
    for (name, rows) in raw
        .iter()
        .filter(|(name, _)| name.as_str() != "native_members")
    {
        let mut values = Vec::new();
        for row in rows {
            budget.sample(super::clock::now())?;
            values.push(json::decode::<serde_json::Value>(row)?);
        }
        catalog.insert(name.as_str(), values);
    }
    let roles = &catalog["native_roles"];
    let runtime = roles
        .iter()
        .filter(|r| r.get("name").and_then(|v| v.as_str()) == Some(d.runtime_role.as_str()))
        .collect::<Vec<_>>();
    if runtime.len() != 1 {
        return Err(deny("native_membership_runtime_role"));
    }
    let runtime_oid = row_u64(runtime[0], "oid")?;
    // The exact role-in-database override wins over database and role defaults.
    // Runtime PGOPTIONS/DSN options are refused by the process binding above.
    let settings = catalog["native_settings"]
        .iter()
        .filter(|r| {
            r.get("database").and_then(|v| v.as_u64()) == Some(d.database_oid as u64)
                && r.get("role").and_then(|v| v.as_u64()) == Some(runtime_oid)
        })
        .collect::<Vec<_>>();
    if settings.len() != 1
        || settings[0]
            .get("config")
            .and_then(|v| v.as_array())
            .is_none_or(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| s.starts_with("search_path="))
                    .collect::<Vec<_>>()
                    != vec!["search_path=pg_catalog, public"]
            })
    {
        return Err(deny("native_membership_runtime_search_path"));
    }
    let role = roles
        .iter()
        .filter(|r| r.get("oid").and_then(|n| n.as_u64()) == Some(d.inspector_oid as u64))
        .collect::<Vec<_>>();
    if role.len() != 1 || row_text(role[0], "name")? != INSPECTOR || !row_bool(role[0], "login")? {
        return Err(deny("native_membership_role"));
    }
    for key in [
        "super",
        "createdb",
        "createrole",
        "inherit",
        "replication",
        "bypassrls",
    ] {
        if row_bool(role[0], key)? {
            return Err(deny("native_membership_role"));
        }
    }
    if catalog["native_memberships"]
        .iter()
        .any(|r| r.get("member").and_then(|v| v.as_u64()) == Some(d.inspector_oid as u64))
    {
        return Err(deny("native_membership_role_membership"));
    }
    let mut table = None;
    for r in &catalog["native_relations"] {
        let oid = row_u64(r, "oid")?;
        for key in [
            "insert",
            "update",
            "delete",
            "truncate",
            "references",
            "trigger",
        ] {
            if row_bool(r, key)? {
                return Err(deny("native_membership_write_capability"));
            }
        }
        if row_u64(r, "owner")? == d.inspector_oid as u64 {
            return Err(deny("native_membership_owner"));
        }
        if oid == d.relay_members_oid as u64 {
            if table.replace(r).is_some() {
                return Err(deny("native_membership_table"));
            }
        } else if row_bool(r, "select")? {
            return Err(deny("native_membership_extra_read"));
        }
    }
    let t = table.ok_or_else(|| deny("native_membership_table"))?;
    if row_text(t, "schema")? != "public"
        || row_text(t, "name")? != "relay_members"
        || row_text(t, "kind")? != "r"
        || row_u64(t, "owner")? != d.relay_members_owner_oid as u64
        || !row_bool(t, "select")?
        || row_bool(t, "rls")?
        || row_bool(t, "force_rls")?
    {
        return Err(deny("native_membership_table"));
    }
    for r in &catalog["native_inheritance"] {
        if row_u64(r, "child")? == d.relay_members_oid as u64
            || row_u64(r, "parent")? == d.relay_members_oid as u64
        {
            return Err(deny("native_membership_inheritance"));
        }
    }
    let expected = [
        ("community_id", 2950, true),
        ("pubkey", 25, true),
        ("role", 25, true),
        ("added_by", 25, false),
        ("created_at", 1184, true),
        ("updated_at", 1184, true),
    ];
    let mut collations = BTreeMap::new();
    for r in &catalog["native_collations"] {
        let oid = row_u64(r, "oid")?;
        if oid == 0 || collations.insert(oid, r).is_some() || !row_bool(r, "deterministic")? {
            return Err(deny("native_membership_nondeterministic_collation"));
        }
    }
    let mut columns = BTreeSet::new();
    let mut pubkey_collation = None;
    for r in &catalog["native_columns"] {
        for key in ["insert", "update", "references"] {
            if row_bool(r, key)? {
                return Err(deny("native_membership_write_capability"));
            }
        }
        if row_u64(r, "relation")? == d.relay_members_oid as u64 {
            let number = row_u64(r, "number")?;
            let (name, ty, required) = expected
                .get(
                    number
                        .checked_sub(1)
                        .ok_or_else(|| deny("native_membership_columns"))?
                        as usize,
                )
                .ok_or_else(|| deny("native_membership_columns"))?;
            let collation = row_u64(r, "collation")?;
            if (*ty == 25 && !collations.contains_key(&collation)) || (*ty != 25 && collation != 0)
            {
                return Err(deny("native_membership_column_collation"));
            }
            if number == 2 {
                pubkey_collation = Some(collation);
            }
            if !columns.insert(number)
                || row_text(r, "name")? != *name
                || row_u64(r, "type")? != *ty
                || row_bool(r, "notnull")? != *required
                || !row_text(r, "generated")?.is_empty()
                || !row_text(r, "identity")?.is_empty()
                || !row_bool(r, "select")?
            {
                return Err(deny("native_membership_columns"));
            }
        } else if row_bool(r, "select")? {
            return Err(deny("native_membership_extra_read"));
        }
    }
    if columns.len() != expected.len() {
        return Err(deny("native_membership_columns"));
    }
    for r in &catalog["native_schemas"] {
        if row_bool(r, "create")? || row_u64(r, "owner")? == d.inspector_oid as u64 {
            return Err(deny("native_membership_schema_capability"));
        }
    }
    for r in &catalog["native_functions"] {
        if row_bool(r, "execute")? || row_u64(r, "owner")? == d.inspector_oid as u64 {
            return Err(deny("native_membership_function_capability"));
        }
    }
    for r in &catalog["native_sequences"] {
        if row_bool(r, "usage")?
            || row_bool(r, "update")?
            || row_u64(r, "owner")? == d.inspector_oid as u64
        {
            return Err(deny("native_membership_sequence_capability"));
        }
    }
    let dbs = &catalog["native_database"];
    if dbs.len() != 1
        || row_u64(&dbs[0], "oid")? != d.database_oid as u64
        || row_text(&dbs[0], "name")? != d.database
        || row_u64(&dbs[0], "owner")? == d.inspector_oid as u64
        || row_bool(&dbs[0], "create")?
        || row_bool(&dbs[0], "temporary")?
    {
        return Err(deny("native_membership_database_capability"));
    }
    let pk = catalog["native_indexes"]
        .iter()
        .filter(|r| {
            r.get("relation").and_then(|v| v.as_u64()) == Some(d.relay_members_oid as u64)
                && r.get("primary").and_then(|v| v.as_bool()) == Some(true)
        })
        .collect::<Vec<_>>();
    if pk.len() != 1
        || !row_bool(pk[0], "valid")?
        || !row_bool(pk[0], "ready")?
        || !row_bool(pk[0], "unique")?
        || pk[0].get("columns") != Some(&serde_json::json!(["community_id", "pubkey"]))
    {
        return Err(deny("native_membership_primary_key"));
    }
    let index_oid = row_u64(pk[0], "oid")?;
    let key_collations = catalog["native_key_collations"]
        .iter()
        .filter(|r| r.get("primary").and_then(|v| v.as_bool()) == Some(true))
        .collect::<Vec<_>>();
    if key_collations.len() != 1
        || row_u64(key_collations[0], "index")? != index_oid
        || row_u64(key_collations[0], "relation")? != d.relay_members_oid as u64
        || key_collations[0].get("collations")
            != Some(&serde_json::json!([
                0,
                pubkey_collation.ok_or_else(|| deny("native_membership_column_collation"))?
            ]))
    {
        return Err(deny("native_membership_index_collation"));
    }
    // Full physical catalog ordering and original bytes, including all function,
    // policy, trigger, constraint and role rows, are independently root-pinned.
    let hash = catalog_digest(raw);
    if hash != d.catalog_sha256 {
        return Err(deny("native_membership_catalog_pin"));
    }
    Ok(hash)
}
fn catalog_digest(raw: &BTreeMap<String, Vec<Vec<u8>>>) -> String {
    let mut bytes = Vec::new();
    for (name, rows) in raw
        .iter()
        .filter(|(name, _)| name.as_str() != "native_members")
    {
        bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        for row in rows {
            bytes.extend_from_slice(&(row.len() as u64).to_be_bytes());
            bytes.extend_from_slice(row);
        }
    }
    llull_buzz_wire::sha256(&bytes)
}
struct FoldedMembership {
    relay_members: Vec<String>,
    original_keys: Vec<KeyMembership>,
    raw_bytes: u64,
    largest_row: u64,
    framed_sha256: String,
}
fn fold(
    raw: &[Vec<u8>],
    owners: &[super::standing::OwnerObservation],
    selection: &receiver::ReceiverSelection,
    budget: &mut Budget,
) -> Result<FoldedMembership> {
    let mut members = Vec::new();
    let mut keys = BTreeSet::new();
    let mut bytes = 0u64;
    let mut largest = 0u64;
    let mut framed = Vec::new();
    for row in raw {
        budget.sample(super::clock::now())?;
        let r: RelayMember = json::decode(row)?;
        if uuid::Uuid::parse_str(&r.community_id)
            .ok()
            .map(|u| u.to_string())
            .as_deref()
            != Some(r.community_id.as_str())
            || !matches!(r.role.as_str(), "owner" | "admin" | "member")
            || r.created_at.is_empty()
            || r.updated_at.is_empty()
            || !keys.insert((r.community_id.clone(), r.pubkey.clone()))
        {
            return Err(deny("native_membership_rows"));
        }
        bytes = bytes
            .checked_add(row.len() as u64)
            .ok_or_else(|| deny("native_membership_bounds"))?;
        largest = largest.max(row.len() as u64);
        if members.len() as u64 >= acquire::ROWS || bytes > acquire::RAW_BYTES {
            return Err(deny("native_membership_bounds"));
        }
        framed.extend_from_slice(&(row.len() as u64).to_be_bytes());
        framed.extend_from_slice(row);
        members.push(
            std::str::from_utf8(row)
                .map_err(|_| deny("native_membership_rows"))?
                .to_owned(),
        );
    }
    let mut decisions = Vec::new();
    for id in &selection.custody_ids {
        let owner = owners
            .iter()
            .filter(|o| &o.scope.custody_id == id)
            .collect::<Vec<_>>();
        if owner.len() != 1 {
            return Err(deny("native_membership_original_key"));
        }
        let s = &owner[0].scope;
        if uuid::Uuid::parse_str(&s.community_id)
            .ok()
            .map(|u| u.to_string())
            .as_deref()
            != Some(s.community_id.as_str())
        {
            return Err(deny("native_membership_original_key"));
        }
        nostr::PublicKey::from_hex(&s.credential_public_key)
            .map_err(|_| deny("native_membership_original_key"))?;
        decisions.push(KeyMembership {
            custody_id: id.clone(),
            community_id: s.community_id.clone(),
            public_key: s.credential_public_key.clone(),
            present: keys.contains(&(s.community_id.clone(), s.credential_public_key.clone())),
        });
    }
    Ok(FoldedMembership {
        relay_members: members,
        original_keys: decisions,
        raw_bytes: bytes,
        largest_row: largest,
        framed_sha256: llull_buzz_wire::sha256(&framed),
    })
}

pub(crate) struct SqlCredentials<'a> {
    pub password: &'a [u8],
    pub certificate: &'a [u8],
    pub client: Option<(&'a [u8], &'a [u8])>,
}
pub(crate) async fn collect(
    profile: &MembershipProfile,
    receivers: &receiver::ReceiverObservations,
    owners: &[super::standing::OwnerObservation],
    auth: &Authenticated,
    credentials: SqlCredentials<'_>,
    budget: &mut Budget,
) -> Result<MembershipObservation> {
    collect_with(
        profile,
        receivers,
        owners,
        auth,
        credentials,
        budget,
        binding,
    )
    .await
}
// The final Linux process/source acquisition and SQL transport are the only
// inert source-control seams; production always supplies the fixed binding.
async fn collect_with(
    profile: &MembershipProfile,
    receivers: &receiver::ReceiverObservations,
    owners: &[super::standing::OwnerObservation],
    auth: &Authenticated,
    credentials: SqlCredentials<'_>,
    budget: &mut Budget,
    mut acquire_binding: impl FnMut(
        &MembershipProfile,
        &receiver::ReceiverSelection,
        &receiver::ReceiverObservation,
        &mut Budget,
    ) -> Result<RuntimeBinding>,
) -> Result<MembershipObservation> {
    let selections = auth
        .profile()
        .native_receivers
        .as_ref()
        .ok_or_else(|| deny("native_membership_profile"))?;
    profile.authenticate(selections)?;
    let acquisition_started_us = budget.sample(super::clock::now())?;
    let selection = selections
        .receivers
        .iter()
        .find(|r| r.receiver_id == profile.receiver_id)
        .ok_or_else(|| deny("native_membership_receiver"))?;
    let observed = receivers
        .receivers
        .iter()
        .find(|r| r.receiver_id == profile.receiver_id)
        .ok_or_else(|| deny("native_membership_receiver"))?;
    let before = acquire_binding(profile, selection, observed, budget)?;
    let mut sql = acquire::NativeSession::connect_membership(
        auth,
        credentials.password,
        credentials.certificate,
        credentials.client,
        budget,
    )
    .await?;
    let first = async {
        let session: NativeSession =
            json::decode(sql.membership_session_metadata(budget).await?.as_bytes())?;
        session.verify(&profile.database)?;
        let snapshot_observed_us = budget.sample(super::clock::now())?;
        let raw = sql
            .collect_membership(profile, &session.snapshot, budget)
            .await?;
        let catalog_sha256 = verify_catalog(&raw, profile, budget)?;
        let folded = fold(&raw["native_members"], owners, selection, budget)?;
        sql.check_snapshot(&session.snapshot, budget).await?;
        let terminal: NativeSession =
            json::decode(sql.membership_session_metadata(budget).await?.as_bytes())?;
        terminal.verify(&profile.database)?;
        if serde_json::to_vec(&session).ok() != serde_json::to_vec(&terminal).ok() {
            return Err(deny("native_membership_session_changed"));
        }
        Ok((session, snapshot_observed_us, catalog_sha256, folded))
    }
    .await;
    let (session, snapshot_observed_us, catalog_sha256, folded) = sql.finish(first, budget).await?;
    if acquire_binding(profile, selection, observed, budget)? != before {
        return Err(deny("native_membership_configuration_changed"));
    }
    let observation = MembershipObservation {
        kind: "llull-buzz-private-native-membership/v1".into(),
        receiver_id: profile.receiver_id.clone(),
        request_sha256: auth.request_hash().into(),
        challenge: auth.request().challenge.clone(),
        observed_us: budget.sample(super::clock::now())?,
        acquisition_started_us,
        snapshot_observed_us,
        source_image_admission_sha256: selection.source_image_admission_sha256.clone(),
        status: if folded.original_keys.iter().any(|k| k.present) {
            "ORIGINAL_KEY_PRESENT"
        } else {
            "ORIGINAL_KEYS_ABSENT_AT_BOUND_SNAPSHOT"
        }
        .into(),
        runtime: before,
        session,
        catalog_sha256,
        relay_members_oid: profile.database.relay_members_oid,
        relay_members_owner_oid: profile.database.relay_members_owner_oid,
        rows: folded.relay_members.len() as u64,
        raw_bytes: folded.raw_bytes,
        largest_row: folded.largest_row,
        framed_sha256: folded.framed_sha256,
        eof: true,
        relay_members: folded.relay_members,
        original_keys: folded.original_keys,
        unresolved: vec![
            "receiver-source-image-admission-unverified".into(),
            "receiver-tls-route-admission-unverified".into(),
            "native-key-membership-after-snapshot-unverified".into(),
            "copied-key-can-mint-until-actual-native-gate-rejects".into(),
            "other-recipient-and-copied-token-domains-unobserved".into(),
            "accepted-earlier-effects-unobserved".into(),
        ],
    };
    receiver::admit_composition(&mut 0, &observation)?;
    auth.current(budget.sample(super::clock::now())?)?;
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::super::{
        authority,
        standing::{HistoryAnchor, OwnerObservation, StandingProfile},
    };
    use super::*;
    use serde_json::json;
    use std::{
        cell::RefCell,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    const COMMUNITY: &str = "00000000-0000-0000-0000-000000000001";
    fn credentials() -> SqlCredentials<'static> {
        SqlCredentials {
            password: b"synthetic-password",
            certificate: b"synthetic-root",
            client: None,
        }
    }
    fn raw(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }
    fn catalogs() -> BTreeMap<String, Vec<Vec<u8>>> {
        let mut c = SOURCES
            .iter()
            .map(|n| (n.to_string(), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        c.get_mut("native_roles").unwrap().push(raw(json!({"oid":42,"name":INSPECTOR,"login":true,"super":false,"createdb":false,"createrole":false,"inherit":false,"replication":false,"bypassrls":false})));
        c.get_mut("native_roles")
            .unwrap()
            .push(raw(json!({"oid":43,"name":"native_runtime","login":true})));
        c.get_mut("native_settings").unwrap().push(raw(
            json!({"database":10,"role":43,"config":["search_path=pg_catalog, public"]}),
        ));
        c.get_mut("native_collations").unwrap().push(raw(
            json!({"oid":100,"schema":"pg_catalog","name":"default","deterministic":true}),
        ));
        c.get_mut("native_key_collations").unwrap().push(raw(
            json!({"index":101,"relation":100,"primary":true,"collations":[0,100]}),
        ));
        c.get_mut("native_database").unwrap().push(raw(json!({"oid":10,"name":"native_buzz","owner":99,"acl":"synthetic","create":false,"temporary":false})));
        c.get_mut("native_relations").unwrap().push(raw(json!({"oid":100,"schema":"public","name":"relay_members","kind":"r","owner":99,"rls":false,"force_rls":false,"select":true,"insert":false,"update":false,"delete":false,"truncate":false,"references":false,"trigger":false})));
        for (index, (name, ty, required)) in [
            ("community_id", 2950, true),
            ("pubkey", 25, true),
            ("role", 25, true),
            ("added_by", 25, false),
            ("created_at", 1184, true),
            ("updated_at", 1184, true),
        ]
        .iter()
        .enumerate()
        {
            c.get_mut("native_columns").unwrap().push(raw(json!({"relation":100,"number":index+1,"name":name,"type":ty,"collation":if *ty==25 {100}else{0},"notnull":required,"generated":"","identity":"","select":true,"insert":false,"update":false,"references":false})));
        }
        c.get_mut("native_schemas").unwrap().push(raw(
            json!({"oid":2200,"name":"public","owner":99,"create":false,"usage":true}),
        ));
        c.get_mut("native_indexes").unwrap().push(raw(json!({"oid":101,"relation":100,"primary":true,"valid":true,"ready":true,"unique":true,"columns":["community_id","pubkey"]})));
        c
    }
    fn profile(c: &BTreeMap<String, Vec<Vec<u8>>>) -> MembershipProfile {
        MembershipProfile {
            kind: "llull-buzz-native-membership-profile/v1".into(),
            receiver_id: "original-native-relay".into(),
            process_environment_sha256: "a".repeat(64),
            database_url_sha256: "b".repeat(64),
            database: NativeDatabase {
                host: "native-db.synthetic.invalid".into(),
                port: 5432,
                database: "native_buzz".into(),
                runtime_role: "native_runtime".into(),
                database_oid: 10,
                inspector_oid: 42,
                server_address: "192.0.2.10".into(),
                server_version_num: 180003,
                system_identifier: "1234567890123456789".into(),
                ssl_root_sha256: llull_buzz_wire::sha256(b"synthetic-root"),
                client_certificate_sha256: None,
                relay_members_oid: 100,
                relay_members_owner_oid: 99,
                catalog_sha256: catalog_digest(c),
            },
        }
    }
    fn session() -> NativeSession {
        NativeSession {
            current_user: INSPECTOR.into(),
            session_user: INSPECTOR.into(),
            inspector_oid: 42,
            database: "native_buzz".into(),
            database_oid: 10,
            address: "192.0.2.10".into(),
            port: 5432,
            version: 180003,
            system_identifier: "1234567890123456789".into(),
            postmaster_started: "2026-10-27 00:00:00+00".into(),
            backend_pid: 1234,
            in_recovery: false,
            ssl: true,
            search_path: "pg_catalog, public".into(),
            read_only: "on".into(),
            isolation: "repeatable read".into(),
            create: false,
            temporary: false,
            snapshot: "1:2:".into(),
        }
    }
    struct Fixture {
        owner: OwnerObservation,
        selection: receiver::ReceiverSelection,
        receivers: receiver::ReceiverObservations,
        profile: MembershipProfile,
        auth: Authenticated,
        budget: Budget,
        signer: Vec<u8>,
        catalogs: BTreeMap<String, Vec<Vec<u8>>>,
    }
    impl Fixture {
        fn new(count: usize) -> Self {
            Self::new_with_client(count, None)
        }
        fn new_with_client(count: usize, client: Option<&[u8]>) -> Self {
            let owner = super::super::standing::synthetic_membership_owner();
            let selection = receiver::ReceiverSelection {
                receiver_id: "original-native-relay".into(),
                custody_ids: vec![owner.scope.custody_id.clone()],
                process: owner.original_process.clone(),
                program: receiver::PROGRAM.into(),
                executable_sha256: "a".repeat(64),
                source_root: "/opt/llull/receiver-source".into(),
                upstream_revision: receiver::UPSTREAM.into(),
                source_image_admission_sha256: "b".repeat(64),
            };
            let mut catalogs = catalogs();
            for n in 0..count {
                catalogs.get_mut("native_members").unwrap().push(raw(json!({"community_id":COMMUNITY,"pubkey":format!("{n:064x}"),"role":"member","added_by":null,"created_at":"2026-10-27T00:00:00+00:00","updated_at":"2026-10-27T00:00:00+00:00"})));
            }
            let mut profile = profile(&catalogs);
            profile.database.client_certificate_sha256 = client.map(llull_buzz_wire::sha256);
            let native = StandingProfile {
                kind: "llull-buzz-native-standing-profile/v1".into(),
                scopes: vec![owner.scope.clone()],
                retained_anchors: BTreeMap::from([(
                    owner.scope.custody_id.clone(),
                    HistoryAnchor {
                        acquisition_sha256: llull_buzz_wire::digest(&owner.history[0]).unwrap(),
                        prefix_records: owner.history.len() as u64,
                        prefix_head_sha256: owner.head_sha256.clone(),
                    },
                )]),
            };
            let receiver_profile = receiver::ReceiverProfile {
                kind: "llull-buzz-native-receiver-profile/v2".into(),
                receivers: vec![selection.clone()],
                membership: Some(profile.clone()),
            };
            let (trust, p, r, signer, now) =
                authority::synthetic_receiver_inputs(native, receiver_profile);
            let mut budget = Budget::new(now, now + 20_000_000).unwrap();
            let auth = Authenticated::admit(&trust, &p, &r, &mut budget, now).unwrap();
            let receivers = receiver::ReceiverObservations {
                kind: "llull-buzz-private-native-receivers/v1".into(),
                request_sha256: auth.request_hash().into(),
                challenge: auth.request().challenge.clone(),
                observed_us: now,
                receivers: vec![receiver::ReceiverObservation {
                    receiver_id: selection.receiver_id.clone(),
                    custody_ids: selection.custody_ids.clone(),
                    observed_us: now,
                    status: "UNKNOWN".into(),
                    source_image_admission_sha256: selection.source_image_admission_sha256.clone(),
                    clock_domain: None,
                    executable: None,
                    policy_files: Vec::new(),
                    conditional_rejections: Vec::new(),
                    unresolved: vec!["synthetic-final-host-acquisition".into()],
                }],
                unresolved: Vec::new(),
                membership: None,
            };
            Self {
                owner,
                selection,
                receivers,
                profile,
                auth,
                budget,
                signer,
                catalogs,
            }
        }
        fn install(
            &self,
            fault: &'static str,
            cleanup: &'static str,
            cancellation: Option<Arc<AtomicBool>>,
        ) -> Rc<RefCell<Vec<String>>> {
            let mut sql = acquire::InertSql::new(
                serde_json::to_string(&session()).unwrap(),
                BTreeMap::new(),
                self.catalogs.clone(),
            );
            sql.fault = fault;
            sql.cleanup_fault = cleanup;
            sql.cancellation = cancellation;
            let log = sql.log.clone();
            sql.install();
            log
        }
        fn runtime(&self) -> RuntimeBinding {
            RuntimeBinding {
                process: self.selection.process.clone(),
                process_environment_sha256: self.profile.process_environment_sha256.clone(),
                database_url_sha256: self.profile.database_url_sha256.clone(),
                host: self.profile.database.host.clone(),
                port: self.profile.database.port,
                database: self.profile.database.database.clone(),
                runtime_role: self.profile.database.runtime_role.clone(),
                require_relay_membership: true,
                allow_nip_oa_auth: false,
                read_replica: false,
                membership_policy_files: Vec::new(),
            }
        }
        async fn run(
            &mut self,
            fault: &'static str,
            cleanup: &'static str,
        ) -> (Result<MembershipObservation>, Rc<RefCell<Vec<String>>>) {
            let log = self.install(fault, cleanup, None);
            let runtime = self.runtime();
            let result = collect_with(
                &self.profile,
                &self.receivers,
                std::slice::from_ref(&self.owner),
                &self.auth,
                credentials(),
                &mut self.budget,
                |_, _, _, _| Ok(runtime.clone()),
            )
            .await;
            (result, log)
        }
    }
    #[tokio::test]
    async fn native_membership_complete_301_rows_absent_key_preserves_scope_and_signed_receipt() {
        let mut f = Fixture::new(301);
        let (result, log) = f.run("", "").await;
        let result = result.unwrap();
        assert_eq!(result.rows, 301);
        assert_eq!(result.relay_members.len(), 301);
        assert!(result.eof);
        let mut framed = Vec::new();
        for row in &result.relay_members {
            json::decode::<RelayMember>(row.as_bytes()).unwrap();
            framed.extend_from_slice(&(row.len() as u64).to_be_bytes());
            framed.extend_from_slice(row.as_bytes());
        }
        assert_eq!(
            result.raw_bytes,
            result
                .relay_members
                .iter()
                .map(|row| row.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            result.largest_row,
            result
                .relay_members
                .iter()
                .map(|row| row.len() as u64)
                .max()
                .unwrap()
        );
        assert_eq!(result.framed_sha256, llull_buzz_wire::sha256(&framed));
        assert_eq!(result.status, "ORIGINAL_KEYS_ABSENT_AT_BOUND_SNAPSHOT");
        assert!(!result.original_keys[0].present);
        assert_eq!(
            result.original_keys[0].community_id,
            f.owner.scope.community_id
        );
        assert_eq!(
            result.original_keys[0].public_key,
            f.owner.scope.credential_public_key
        );
        assert_eq!(result.runtime.runtime_role, "native_runtime");
        assert_eq!(result.session.current_user, INSPECTOR);
        assert!(result
            .unresolved
            .contains(&"accepted-earlier-effects-unobserved".into()));
        assert!(result
            .unresolved
            .contains(&"copied-key-can-mint-until-actual-native-gate-rejects".into()));
        let value = serde_json::to_value(&result).unwrap();
        let hash = llull_buzz_wire::sha256(&serde_json::to_vec(&value).unwrap());
        let now = super::super::clock::now();
        let signed = f
            .auth
            .sign(result, &f.signer, now, f.auth.expires())
            .unwrap();
        f.auth
            .verify_response(&signed, &hash, super::super::clock::now())
            .unwrap();
        let log = log.borrow();
        assert_eq!(log.last().unwrap(), "close");
        assert!(log.iter().any(|s| s == "execute:ROLLBACK"));
        assert_eq!(
            log.iter()
                .filter(|s| s.starts_with("execute:DECLARE "))
                .count(),
            SOURCES.len()
        );
        assert!(log
            .iter()
            .any(|s| s == "execute:LOCK TABLE public.relay_members IN ACCESS SHARE MODE"));
        assert!(!log.iter().any(|s| s.contains("buzz_inspection.v_")));
    }
    #[tokio::test]
    async fn native_membership_present_current_key_is_not_provider_enrollment_retirement() {
        let mut f = Fixture::new(0);
        f.owner.local_status = "RETIRED".into();
        f.catalogs.get_mut("native_members").unwrap().push(raw(json!({"community_id":COMMUNITY,"pubkey":f.owner.scope.credential_public_key,"role":"member","added_by":null,"created_at":"2026-10-27T00:00:00+00:00","updated_at":"2026-10-27T00:00:00+00:00"})));
        let (result, _) = f.run("", "").await;
        let result = result.unwrap();
        assert!(result.original_keys[0].present);
        assert_eq!(result.status, "ORIGINAL_KEY_PRESENT");
        assert_eq!(f.owner.local_status, "RETIRED");
    }
    #[tokio::test]
    async fn native_membership_same_key_other_community_and_other_key_same_community_are_absent() {
        let mut f = Fixture::new(1);
        f.catalogs.get_mut("native_members").unwrap().push(raw(json!({"community_id":"00000000-0000-0000-0000-000000000002","pubkey":f.owner.scope.credential_public_key,"role":"owner","added_by":null,"created_at":"2026-10-27T00:00:00+00:00","updated_at":"2026-10-27T00:00:00+00:00"})));
        let (result, _) = f.run("", "").await;
        assert!(!result.unwrap().original_keys[0].present);
    }
    #[tokio::test]
    async fn native_membership_sql_collation_equality_cannot_be_replaced_by_byte_absence() {
        // Semantic fixture for an unsupported case-insensitive DB collation;
        // this does not execute or claim an installed PostgreSQL collation.
        let lower = "a".repeat(64);
        let upper = "A".repeat(64);
        assert_ne!(lower.as_bytes(), upper.as_bytes());
        assert!(lower.eq_ignore_ascii_case(&upper));
        let mut f = Fixture::new(0);
        f.catalogs.get_mut("native_members").unwrap().push(raw(json!({"community_id":COMMUNITY,"pubkey":f.owner.scope.credential_public_key.to_uppercase(),"role":"member","added_by":null,"created_at":"2026-10-27T00:00:00+00:00","updated_at":"2026-10-27T00:00:00+00:00"})));
        f.catalogs.get_mut("native_collations").unwrap()[0] = raw(
            json!({"oid":100,"schema":"pg_catalog","name":"case-insensitive-synthetic","deterministic":false}),
        );
        let (result, log) = f.run("", "").await;
        assert!(matches!(
            result,
            Err(super::super::InspectionError::Denied(
                "native_membership_nondeterministic_collation"
            ))
        ));
        assert!(!log
            .borrow()
            .iter()
            .any(|s| s.starts_with("scalar:") && s.contains("FROM public.relay_members")));
        assert_eq!(log.borrow().last().unwrap(), "close");
        let mut f = Fixture::new(0);
        f.catalogs.get_mut("native_key_collations").unwrap()[0] =
            raw(json!({"index":101,"relation":100,"primary":true,"collations":[0,999]}));
        let (result, _) = f.run("", "").await;
        assert!(matches!(
            result,
            Err(super::super::InspectionError::Denied(
                "native_membership_index_collation"
            ))
        ));
    }
    #[tokio::test]
    async fn native_membership_missing_eof_digest_timeout_and_cleanup_are_never_absence() {
        for (fault, cleanup) in [
            ("early-eof", ""),
            ("chunk-digest", ""),
            ("chunk-order", ""),
            ("fetch-timeout", ""),
            ("cursor-close", ""),
            ("", "rollback"),
            ("", "connection-close"),
        ] {
            let mut f = Fixture::new(1);
            let (result, log) = f.run(fault, cleanup).await;
            assert!(result.is_err(), "{fault}/{cleanup}");
            let log = log.borrow();
            assert_eq!(log.last().unwrap(), "close");
            assert!(log.iter().any(|s| s == "execute:ROLLBACK"));
        }
    }
    #[tokio::test]
    async fn native_membership_cancellation_during_sql_still_closes_owned_cursor_and_connection() {
        use futures_util::FutureExt;
        let mut f = Fixture::new(1);
        let flag = Arc::new(AtomicBool::new(false));
        let watched = flag.clone();
        f.budget.watch(
            futures_util::future::poll_fn(move |_| {
                if watched.load(Ordering::SeqCst) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .boxed()
            .shared(),
        );
        let log = f.install("cancel-fetch", "", Some(flag));
        let runtime = f.runtime();
        assert!(collect_with(
            &f.profile,
            &f.receivers,
            std::slice::from_ref(&f.owner),
            &f.auth,
            credentials(),
            &mut f.budget,
            |_, _, _, _| Ok(runtime.clone())
        )
        .await
        .is_err());
        let log = log.borrow();
        assert!(log
            .iter()
            .any(|s| s == "execute:CLOSE buzz_inspection_payload"));
        assert!(log.iter().any(|s| s == "execute:ROLLBACK"));
        assert_eq!(log.last().unwrap(), "close");
    }
    #[tokio::test]
    async fn native_membership_role_catalog_and_session_fail_closed_before_absence() {
        for (source, key, value) in [
            ("native_roles", "super", json!(true)),
            ("native_roles", "inherit", json!(true)),
            ("native_relations", "rls", json!(true)),
            ("native_relations", "kind", json!("v")),
            ("native_relations", "insert", json!(true)),
            ("native_columns", "update", json!(true)),
            ("native_schemas", "create", json!(true)),
            ("native_database", "temporary", json!(true)),
            ("native_indexes", "valid", json!(false)),
            ("native_settings", "config", json!(["search_path=public"])),
        ] {
            let mut f = Fixture::new(1);
            let mut v: serde_json::Value = serde_json::from_slice(&f.catalogs[source][0]).unwrap();
            v[key] = value;
            f.catalogs.get_mut(source).unwrap()[0] = raw(v);
            let (result, log) = f.run("", "").await;
            assert!(result.is_err(), "{source}.{key}");
            assert_eq!(log.borrow().last().unwrap(), "close");
            assert!(!log
                .borrow()
                .iter()
                .any(|s| s.starts_with("scalar:") && s.contains("FROM public.relay_members")));
        }
        let p = profile(&catalogs());
        for key in [
            "ssl",
            "read_only",
            "system_identifier",
            "inspector_oid",
            "in_recovery",
            "address",
            "current_user",
        ] {
            let mut v = serde_json::to_value(session()).unwrap();
            v[key] = match key {
                "ssl" => json!(false),
                "in_recovery" => json!(true),
                "inspector_oid" => json!(43),
                _ => json!("wrong"),
            };
            assert!(
                serde_json::from_value::<NativeSession>(v)
                    .unwrap()
                    .verify(&p.database)
                    .is_err(),
                "{key}"
            );
        }
    }
    #[tokio::test]
    async fn native_membership_unknown_receiver_process_or_environment_drift_never_publish() {
        let mut f = Fixture::new(1);
        assert!(binding(
            &f.profile,
            &f.selection,
            &f.receivers.receivers[0],
            &mut f.budget
        )
        .is_err());
        for process in [false, true] {
            let mut f = Fixture::new(1);
            let log = f.install("", "", None);
            let runtime = f.runtime();
            let mut calls = 0;
            let result = collect_with(
                &f.profile,
                &f.receivers,
                std::slice::from_ref(&f.owner),
                &f.auth,
                credentials(),
                &mut f.budget,
                |_, _, _, _| {
                    calls += 1;
                    let mut r = runtime.clone();
                    if calls > 1 {
                        if process {
                            r.process.start_ticks += 1;
                        } else {
                            r.process_environment_sha256 = "c".repeat(64);
                        }
                    }
                    Ok(r)
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(log.borrow().last().unwrap(), "close");
        }
        let mut f = Fixture::new(1);
        let log = f.install("", "", None);
        let runtime = f.runtime();
        assert!(collect_with(
            &f.profile,
            &f.receivers,
            std::slice::from_ref(&f.owner),
            &f.auth,
            credentials(),
            &mut f.budget,
            |_, _, _, budget| {
                budget.sample(super::super::clock::now() + 20_000_001)?;
                Ok(runtime.clone())
            }
        )
        .await
        .is_err());
        acquire::InertSql::clear();
        assert!(log.borrow().is_empty());
    }
    #[test]
    fn native_membership_loaded_environment_admits_maintained_tls_dsn_and_refuses_gate_or_locator_overrides(
    ) {
        let f = Fixture::new(0);
        let dsn="postgresql://native_runtime:synthetic@native-db.synthetic.invalid:5432/native_buzz?sslmode=verify-full&sslrootcert=/run/database-ca.pem&sslcert=/run/cloud-sql/client.pem&sslkey=/run/cloud-sql/client.key";
        let env = |dsn: &str, required: &str, oa: Option<&str>, replica: Option<&str>| {
            let mut s = format!("DATABASE_URL={dsn}\0BUZZ_REQUIRE_RELAY_MEMBERSHIP={required}\0");
            if let Some(oa) = oa {
                s += &format!("BUZZ_ALLOW_NIP_OA_AUTH={oa}\0");
            }
            if let Some(replica) = replica {
                s += &format!("READ_DATABASE_URL={replica}\0");
            }
            s.into_bytes()
        };
        let check = |data: Vec<u8>, url: &str| {
            let mut p = f.profile.clone();
            p.process_environment_sha256 = llull_buzz_wire::sha256(&data);
            p.database_url_sha256 = llull_buzz_wire::sha256(url.as_bytes());
            environment(&data, &p, &f.selection.process)
        };
        assert!(check(env(dsn, "true", None, None), dsn).is_ok());
        assert!(check(env(dsn, "1", Some("false"), Some("  ")), dsn).is_ok());
        for (required, oa, replica) in [
            ("false", None, None),
            ("true", Some("true"), None),
            ("true", Some("typo"), None),
            ("true", None, Some("postgresql://replica.invalid/buzz")),
        ] {
            assert!(check(env(dsn, required, oa, replica), dsn).is_err());
        }
        for suffix in [
            "&host=other.invalid",
            "&hostaddr=192.0.2.99",
            "&dbname=other",
            "&service=other",
            "&sslmode=disable",
        ] {
            let bad = format!("{dsn}{suffix}");
            assert!(check(env(&bad, "true", None, None), &bad).is_err());
        }
        let mut data = env(dsn, "true", None, None);
        data.extend_from_slice(b"DATABASE_URL=postgresql://other.invalid/native_buzz\0");
        assert!(check(data, dsn).is_err());
        let data = env(dsn, "true", None, None);
        assert!(environment(&data, &f.profile, &f.selection.process).is_err());
    }
    #[tokio::test]
    async fn native_membership_preflight_and_composition_refuse_bounds_before_partial_absence() {
        let mut f = Fixture::new(10_001);
        let (result, log) = f.run("", "").await;
        assert!(result.is_err());
        assert!(!log
            .borrow()
            .iter()
            .any(|s| s.starts_with("execute:DECLARE ")
                && s.contains("SELECT to_jsonb(r)::text AS raw FROM public.relay_members r")));
        let mut f = Fixture::new(1);
        let (result, _) = f.run("oversize", "").await;
        assert!(result.is_err());
        let mut bytes = 0;
        assert!(
            receiver::admit_composition(&mut bytes, &"x".repeat(llull_buzz_wire::MAX_BYTES))
                .is_err()
        );
    }
    #[test]
    fn native_membership_forward_optin_preserves_legacy_v1_and_closed_shapes() {
        let f = Fixture::new(0);
        let mut p = f.auth.profile().native_receivers.as_ref().unwrap().clone();
        p.kind = "llull-buzz-native-receiver-profile/v1".into();
        assert!(p.authenticate(&f.auth).is_err());
        p.membership = None;
        assert!(p.authenticate(&f.auth).is_ok());
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("membership").is_none());
        let legacy: receiver::ReceiverProfile = serde_json::from_value(v.clone()).unwrap();
        assert!(legacy.membership.is_none());
        legacy.authenticate(&f.auth).unwrap();
        let mut legacy_null = v;
        legacy_null["membership"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<receiver::ReceiverProfile>(legacy_null).is_err());
        let forward =
            serde_json::to_value(f.auth.profile().native_receivers.as_ref().unwrap()).unwrap();
        serde_json::from_value::<receiver::ReceiverProfile>(forward.clone())
            .unwrap()
            .authenticate(&f.auth)
            .unwrap();
        let mut forward_missing = forward.clone();
        forward_missing
            .as_object_mut()
            .unwrap()
            .remove("membership");
        let missing: receiver::ReceiverProfile = serde_json::from_value(forward_missing).unwrap();
        assert!(missing.authenticate(&f.auth).is_err());
        let mut forward_null = forward;
        forward_null["membership"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<receiver::ReceiverProfile>(forward_null).is_err());
        let mut v = serde_json::to_value(&f.profile).unwrap();
        v["arbitrary_sql"] = json!("SELECT true");
        assert!(serde_json::from_value::<MembershipProfile>(v).is_err());
    }
    #[tokio::test]
    async fn native_membership_client_tls_requires_exact_optin_and_pinned_certificate() {
        let mut f = Fixture::new(0);
        let log = f.install("", "", None);
        // No cert opt-in means no private client material can enter the driver.
        assert!(acquire::NativeSession::connect_membership(
            &f.auth,
            b"synthetic-password",
            b"synthetic-root",
            Some((b"synthetic-client", b"synthetic-key")),
            &mut f.budget
        )
        .await
        .is_err());
        acquire::InertSql::clear();
        assert!(log.borrow().is_empty());
        let mut f = Fixture::new_with_client(0, Some(b"synthetic-client"));
        let log = f.install("", "", None);
        assert!(acquire::NativeSession::connect_membership(
            &f.auth,
            b"synthetic-password",
            b"synthetic-root",
            Some((b"wrong-client", b"synthetic-key")),
            &mut f.budget
        )
        .await
        .is_err());
        acquire::InertSql::clear();
        assert!(log.borrow().is_empty());
        let mut f = Fixture::new_with_client(0, Some(b"synthetic-client"));
        let log = f.install("", "", None);
        let runtime = f.runtime();
        assert!(collect_with(
            &f.profile,
            &f.receivers,
            std::slice::from_ref(&f.owner),
            &f.auth,
            SqlCredentials {
                password: b"synthetic-password",
                certificate: b"synthetic-root",
                client: Some((b"synthetic-client", b"synthetic-key"))
            },
            &mut f.budget,
            |_, _, _, _| Ok(runtime.clone())
        )
        .await
        .is_ok());
        assert_eq!(log.borrow().last().unwrap(), "close");
    }
}
