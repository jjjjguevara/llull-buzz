//! Fixed effective-capability catalog projections; no caller role/SQL allowlist.
use super::{
    authority::{Database, INSPECTOR, VIEW_OWNER},
    deny, Result,
};
use serde::Deserialize;

/// One startup/session contract; no ambient or user-selected schema is admitted.
pub(crate) const INSPECTION_SEARCH_PATH: &str = "pg_catalog, buzz_inspection";
pub(crate) struct CatalogQuery {
    pub name: &'static str,
    pub sql: &'static str,
}
pub(crate) const QUERIES:&[CatalogQuery]=&[
CatalogQuery{name:"database",sql:"SELECT json_build_object('oid',d.oid,'name',d.datname,'owner',d.datdba,'acl',d.datacl::text,'create',has_database_privilege(current_user,d.oid,'CREATE'),'temporary',has_database_privilege(current_user,d.oid,'TEMPORARY'),'owner_create',has_database_privilege('buzz_recovery_view_owner',d.oid,'CREATE'),'owner_temporary',has_database_privilege('buzz_recovery_view_owner',d.oid,'TEMPORARY'))::text AS raw FROM pg_catalog.pg_database d WHERE d.datname=current_database() ORDER BY d.oid"},
CatalogQuery{name:"triggers",sql:"SELECT json_build_object('oid',t.oid,'relation',t.tgrelid,'schema',n.nspname,'table',r.relname,'name',t.tgname,'function',t.tgfoid,'function_schema',pn.nspname,'function_name',p.proname,'enabled',t.tgenabled::text,'type',t.tgtype,'internal',t.tgisinternal,'constraint',t.tgconstraint,'qualification',t.tgqual::text,'arguments',encode(t.tgargs,'hex'),'columns',t.tgattr::text,'deferrable',t.tgdeferrable,'initially_deferred',t.tginitdeferred,'old_transition',t.tgoldtable,'new_transition',t.tgnewtable,'definition',pg_get_triggerdef(t.oid,false),'catalog',to_jsonb(t))::text AS raw FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class r ON r.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY t.oid"},
CatalogQuery{name:"constraints",sql:"SELECT json_build_object('oid',c.oid,'relation',c.conrelid,'schema',n.nspname,'table',r.relname,'name',c.conname,'kind',c.contype::text,'columns',ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.ord),'referenced_relation',c.confrelid,'referenced_schema',rn.nspname,'referenced_table',rr.relname,'referenced_columns',ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum ORDER BY k.ord),'index',c.conindid,'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,'local',c.conislocal,'inherit_count',c.coninhcount,'update_action',c.confupdtype::text,'delete_action',c.confdeltype::text,'match',c.confmatchtype::text,'definition',pg_get_constraintdef(c.oid,false),'expression',pg_get_expr(c.conbin,c.conrelid,false),'catalog',to_jsonb(c))::text AS raw FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace LEFT JOIN pg_catalog.pg_class rr ON rr.oid=c.confrelid LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=rr.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY c.oid"},
CatalogQuery{name:"indexes",sql:"SELECT json_build_object('oid',i.indexrelid,'relation',i.indrelid,'schema',n.nspname,'table',r.relname,'name',idx.relname,'owner',idx.relowner,'method',am.amname,'unique',i.indisunique,'primary',i.indisprimary,'exclusion',i.indisexclusion,'immediate',i.indimmediate,'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'nulls_not_distinct',i.indnullsnotdistinct,'key_count',i.indnkeyatts,'attribute_count',i.indnatts,'columns',ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord),'predicate',pg_get_expr(i.indpred,i.indrelid,false),'expressions',pg_get_expr(i.indexprs,i.indrelid,false),'definition',pg_get_indexdef(i.indexrelid,0,false),'catalog',to_jsonb(i))::text AS raw FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class r ON r.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=idx.relam WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY i.indexrelid"},
CatalogQuery{name:"roles",sql:"SELECT json_build_object('oid',oid,'name',rolname,'super',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,'inherit',rolinherit,'login',rolcanlogin,'replication',rolreplication,'bypassrls',rolbypassrls)::text AS raw FROM pg_catalog.pg_roles ORDER BY oid"},
CatalogQuery{name:"memberships",sql:"SELECT json_build_object('role',roleid,'member',member,'grantor',grantor,'admin',admin_option)::text AS raw FROM pg_catalog.pg_auth_members ORDER BY roleid,member,grantor"},
CatalogQuery{name:"relations",sql:"SELECT json_build_object('oid',c.oid,'schema',n.nspname,'name',c.relname,'kind',c.relkind::text,'owner',c.relowner,'rls',c.relrowsecurity,'force_rls',c.relforcerowsecurity,'acl',c.relacl::text,'options',c.reloptions,'definition',CASE WHEN c.relkind='v' THEN encode(sha256(convert_to(pg_get_viewdef(c.oid,true),'UTF8')),'hex') ELSE NULL END,'select',has_table_privilege(current_user,c.oid,'SELECT'),'insert',has_table_privilege(current_user,c.oid,'INSERT'),'update',has_table_privilege(current_user,c.oid,'UPDATE'),'delete',has_table_privilege(current_user,c.oid,'DELETE'),'truncate',has_table_privilege(current_user,c.oid,'TRUNCATE'),'references',has_table_privilege(current_user,c.oid,'REFERENCES'),'trigger',has_table_privilege(current_user,c.oid,'TRIGGER'))::text AS raw FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','v','m','f') AND left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY c.oid"},
CatalogQuery{name:"columns",sql:"SELECT json_build_object('relation',c.oid,'number',a.attnum,'name',a.attname,'type',a.atttypid,'typmod',a.atttypmod,'notnull',a.attnotnull,'generated',a.attgenerated::text,'identity',a.attidentity::text,'collation',a.attcollation,'acl',a.attacl::text,'select',has_column_privilege(current_user,c.oid,a.attnum,'SELECT'),'insert',has_column_privilege(current_user,c.oid,a.attnum,'INSERT'),'update',has_column_privilege(current_user,c.oid,a.attnum,'UPDATE'),'references',has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES'))::text AS raw FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f') AND left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY c.oid,a.attnum"},
CatalogQuery{name:"schemas",sql:"SELECT json_build_object('oid',oid,'name',nspname,'owner',nspowner,'acl',nspacl::text,'create',has_schema_privilege(current_user,oid,'CREATE'),'usage',has_schema_privilege(current_user,oid,'USAGE'))::text AS raw FROM pg_catalog.pg_namespace WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema' ORDER BY oid"},
CatalogQuery{name:"functions",sql:"SELECT json_build_object('oid',p.oid,'schema',n.nspname,'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'owner',p.proowner,'security_definer',p.prosecdef,'config',p.proconfig,'acl',p.proacl::text,'execute',has_function_privilege(current_user,p.oid,'EXECUTE'),'body_sha256',encode(sha256(convert_to(p.prosrc,'UTF8')),'hex'),'definition_sha256',encode(sha256(convert_to(CASE WHEN p.prokind='a' THEN (SELECT to_jsonb(a)::text FROM pg_catalog.pg_aggregate a WHERE a.aggfnoid=p.oid) ELSE pg_get_functiondef(p.oid) END,'UTF8')),'hex'))::text AS raw FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND p.prokind IN ('f','p','w','a') ORDER BY p.oid"},
CatalogQuery{name:"sequences",sql:"SELECT json_build_object('oid',c.oid,'schema',n.nspname,'name',c.relname,'owner',c.relowner,'acl',c.relacl::text,'select',has_sequence_privilege(current_user,c.oid,'SELECT'),'usage',has_sequence_privilege(current_user,c.oid,'USAGE'),'update',has_sequence_privilege(current_user,c.oid,'UPDATE'))::text AS raw FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY c.oid"},
CatalogQuery{name:"policies",sql:"SELECT json_build_object('oid',p.oid,'relation',p.polrelid,'name',p.polname,'command',p.polcmd::text,'permissive',p.polpermissive,'roles',p.polroles,'using',pg_get_expr(p.polqual,p.polrelid),'check',pg_get_expr(p.polwithcheck,p.polrelid))::text AS raw FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' ORDER BY p.oid"},
];
pub(crate) const SESSION_SQL:&str="WITH header AS MATERIALIZED (SELECT json_build_object('current_user',current_user,'session_user',session_user,'database',current_database(),'database_oid',(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),'address',inet_server_addr()::text,'port',inet_server_port(),'version',current_setting('server_version_num')::integer,'search_path',current_setting('search_path'),'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),'create',has_database_privilege(current_user,current_database(),'CREATE'),'temporary',has_database_privilege(current_user,current_database(),'TEMPORARY'),'snapshot',pg_current_snapshot()::text)::text AS raw) SELECT CASE WHEN octet_length(raw)<=8192 THEN raw ELSE '{\"refused\":\"session_scalar_bound\"}' END FROM header";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Session {
    current_user: String,
    session_user: String,
    database: String,
    database_oid: u32,
    address: Option<String>,
    port: Option<u16>,
    version: i32,
    search_path: String,
    read_only: String,
    isolation: String,
    create: bool,
    temporary: bool,
    pub snapshot: String,
}
impl Session {
    pub(crate) fn verify(&self, expected: &Database) -> Result<()> {
        if self.current_user != INSPECTOR
            || self.session_user != INSPECTOR
            || self.database != expected.database
            || self.database_oid != expected.database_oid
            || self.address.as_deref() != Some(&expected.server_address)
            || self.port != Some(expected.port)
            || self.version != expected.server_version_num
            || self.search_path != INSPECTION_SEARCH_PATH
            || self.read_only != "on"
            || self.isolation != "repeatable read"
            || self.create
            || self.temporary
            || self.snapshot.is_empty()
            || self.snapshot.len() > 4096
        {
            return Err(deny("inspection_session"));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Role {
    oid: u32,
    name: String,
    #[serde(rename = "super")]
    superuser: bool,
    createdb: bool,
    createrole: bool,
    inherit: bool,
    login: bool,
    replication: bool,
    bypassrls: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Membership {
    role: u32,
    member: u32,
    grantor: u32,
    admin: bool,
}
pub(crate) fn verify_roles(
    roles: &[Role],
    memberships: &[Membership],
    expected: &Database,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    let mut found = std::collections::BTreeSet::new();
    for role in roles {
        if !seen.insert(role.oid) {
            return Err(deny("catalog_duplicate"));
        }
        for (name, oid, login) in [
            (INSPECTOR, expected.inspector_oid, true),
            (VIEW_OWNER, expected.view_owner_oid, false),
        ] {
            if role.name == name || role.oid == oid {
                if role.name != name
                    || role.oid != oid
                    || role.login != login
                    || role.superuser
                    || role.createdb
                    || role.createrole
                    || role.inherit
                    || role.replication
                    || role.bypassrls
                {
                    return Err(deny("inspection_role"));
                }
                found.insert(name);
            }
        }
    }
    if found.len() != 2 {
        return Err(deny("inspection_role_missing"));
    }
    for membership in memberships {
        if [expected.inspector_oid, expected.view_owner_oid].contains(&membership.role)
            || [expected.inspector_oid, expected.view_owner_oid].contains(&membership.member)
        {
            return Err(deny("inspection_inherited_capability"));
        }
        let _ = (membership.admin, membership.grantor); // Complete records retained in the catalog digest.
    }
    Ok(())
}

fn string<'a>(row: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    row.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| deny("catalog_shape"))
}
fn boolean(row: &serde_json::Value, name: &str) -> Result<bool> {
    row.get(name)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| deny("catalog_shape"))
}
fn oid(row: &serde_json::Value, name: &str) -> Result<u32> {
    row.get(name)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| deny("catalog_shape"))
}
/// Inputs are complete retained catalog traversal rows, not caller policy flags.
/// The SQL transport and complete EOF custody are verified by the acquisition owner.
pub(crate) fn verify_effective_capabilities(
    rows: &std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    expected: &Database,
) -> Result<()> {
    if rows.len() != QUERIES.len() || QUERIES.iter().any(|q| !rows.contains_key(q.name)) {
        return Err(deny("catalog_scope"));
    }
    verify_database(&rows["database"], expected)?;
    verify_enforcement(rows)?;
    let mut view_oids = std::collections::BTreeSet::new();
    let mut views = std::collections::BTreeSet::new();
    let mut all_relations = std::collections::BTreeSet::new();
    for row in &rows["relations"] {
        let relation_oid = oid(row, "oid")?;
        if !all_relations.insert(relation_oid) {
            return Err(deny("catalog_duplicate"));
        }
        let schema = string(row, "schema")?;
        let name = string(row, "name")?;
        for capability in [
            "insert",
            "update",
            "delete",
            "truncate",
            "references",
            "trigger",
        ] {
            if boolean(row, capability)? {
                return Err(deny("inspection_mutation"));
            }
        }
        let selected = if schema == "buzz_inspection" {
            name.strip_prefix("v_")
                .and_then(|n| super::relations::relation(n).ok())
        } else {
            None
        };
        match selected {
            Some(relation) => {
                if string(row, "kind")? != "v"
                    || oid(row, "owner")? != expected.view_owner_oid
                    || !boolean(row, "select")?
                    || boolean(row, "rls")?
                    || boolean(row, "force_rls")?
                    || string(row, "definition")?
                        != expected
                            .view_definition_sha256
                            .get(relation.name)
                            .ok_or_else(|| deny("view_scope"))?
                {
                    return Err(deny("inspection_view_binding"));
                }
                let options = row
                    .get("options")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| deny("catalog_shape"))?;
                if options.len() != 1 || options[0].as_str() != Some("security_barrier=true") {
                    return Err(deny("inspection_view_barrier"));
                }
                if !views.insert(relation.name) || !view_oids.insert(relation_oid) {
                    return Err(deny("catalog_duplicate"));
                }
            }
            None => {
                if schema == "buzz_inspection"
                    || boolean(row, "select")?
                    || oid(row, "owner")? == expected.inspector_oid
                    || oid(row, "owner")? == expected.view_owner_oid
                {
                    return Err(deny("inspection_base_or_unselected_access"));
                }
            }
        }
    }
    if views.len() != super::relations::RELATIONS.len() {
        return Err(deny("inspection_view_missing"));
    }
    let mut columns = std::collections::BTreeSet::new();
    for row in &rows["columns"] {
        let relation = oid(row, "relation")?;
        let number = oid(row, "number")?;
        if !columns.insert((relation, number)) || !all_relations.contains(&relation) {
            return Err(deny("catalog_column_binding"));
        }
        for capability in ["insert", "update", "references"] {
            if boolean(row, capability)? {
                return Err(deny("inspection_column_mutation"));
            }
        }
        if !view_oids.contains(&relation) && boolean(row, "select")? {
            return Err(deny("inspection_column_secret_access"));
        }
        if view_oids.contains(&relation) {
            let (name, type_oid) = match number {
                1 => ("row_sha256", 25),
                2 => ("row_key", 3802),
                3 => ("metadata", 3802),
                _ => return Err(deny("inspection_view_columns")),
            };
            if string(row, "name")? != name
                || oid(row, "type")? != type_oid
                || !boolean(row, "select")?
            {
                return Err(deny("inspection_view_columns"));
            }
        }
    }
    if view_oids
        .iter()
        .any(|view| (1..=3).any(|column| !columns.contains(&(*view, column))))
    {
        return Err(deny("inspection_view_columns"));
    }
    let mut found_schema = false;
    for row in &rows["schemas"] {
        if boolean(row, "create")? || oid(row, "owner")? == expected.inspector_oid {
            return Err(deny("inspection_schema_create"));
        }
        if string(row, "name")? == "buzz_inspection" {
            if found_schema
                || oid(row, "owner")? != expected.view_owner_oid
                || !boolean(row, "usage")?
            {
                return Err(deny("inspection_schema_binding"));
            }
            found_schema = true;
        } else if oid(row, "owner")? == expected.view_owner_oid {
            return Err(deny("inspection_unselected_ownership"));
        }
    }
    if !found_schema {
        return Err(deny("inspection_schema_missing"));
    }
    for row in &rows["functions"] {
        if boolean(row, "execute")?
            || [expected.inspector_oid, expected.view_owner_oid].contains(&oid(row, "owner")?)
        {
            return Err(deny("inspection_application_execution"));
        }
    }
    for row in &rows["sequences"] {
        if ["select", "usage", "update"]
            .iter()
            .any(|capability| boolean(row, capability).unwrap_or(true))
            || [expected.inspector_oid, expected.view_owner_oid].contains(&oid(row, "owner")?)
        {
            return Err(deny("inspection_sequence_capability"));
        }
    }
    Ok(())
}

fn names<'a>(row: &'a serde_json::Value, field: &str) -> Result<Vec<&'a str>> {
    row.get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| deny("catalog_shape"))?
        .iter()
        .map(|v| v.as_str().ok_or_else(|| deny("catalog_shape")))
        .collect()
}
fn nonempty(row: &serde_json::Value, field: &str) -> Result<()> {
    if string(row, field)?.is_empty() {
        return Err(deny("catalog_definition"));
    }
    Ok(())
}
fn verify_database(rows: &[serde_json::Value], expected: &Database) -> Result<()> {
    if rows.len() != 1 {
        return Err(deny("inspection_database_scope"));
    }
    let row = &rows[0];
    if oid(row, "oid")? != expected.database_oid
        || string(row, "name")? != expected.database
        || [expected.inspector_oid, expected.view_owner_oid].contains(&oid(row, "owner")?)
        || ["create", "temporary", "owner_create", "owner_temporary"]
            .iter()
            .any(|field| boolean(row, field).unwrap_or(true))
    {
        return Err(deny("inspection_database_capability"));
    }
    // NULL denotes the server's default ACL, not an omitted attestation. Both
    // direct and PUBLIC/inherited rights are reflected in the effective flags.
    match row.get("acl") {
        Some(serde_json::Value::Null | serde_json::Value::String(_)) => Ok(()),
        _ => Err(deny("catalog_shape")),
    }
}
/// Closed original enforcement structure plus exact live definition custody.
/// This does not turn source migration hashes into installed evidence: the
/// operator-authenticated manifest must independently bind these actual rows.
fn verify_enforcement(
    rows: &std::collections::BTreeMap<String, Vec<serde_json::Value>>,
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut tables = BTreeMap::new();
    for row in &rows["relations"] {
        if string(row, "schema")? == "public"
            && (super::relations::RELATIONS
                .iter()
                .any(|r| r.name == string(row, "name").unwrap_or(""))
                || INTERVENING_TABLES.contains(&string(row, "name").unwrap_or("")))
        {
            if string(row, "kind")? != "r"
                || tables
                    .insert(string(row, "name")?, oid(row, "oid")?)
                    .is_some()
            {
                return Err(deny("inspection_original_relation"));
            }
        }
    }
    if tables.len() != super::relations::RELATIONS.len() + INTERVENING_TABLES.len() {
        return Err(deny("inspection_original_relation_missing"));
    }
    let original = |row: &serde_json::Value| -> Result<bool> {
        let name = string(row, "table")?;
        if string(row, "schema")? == "public" && tables.contains_key(name) {
            if tables[name] != oid(row, "relation")? {
                return Err(deny("catalog_original_binding"));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    };
    let mut indexes = BTreeMap::new();
    for row in &rows["indexes"] {
        let id = oid(row, "oid")?;
        if indexes.insert(id, row).is_some() {
            return Err(deny("catalog_duplicate"));
        }
        if !original(row)? {
            continue;
        }
        nonempty(row, "definition")?;
        if !boolean(row, "valid")?
            || !boolean(row, "ready")?
            || !boolean(row, "live")?
            || !boolean(row, "immediate")?
            || boolean(row, "exclusion")?
            || boolean(row, "nulls_not_distinct")?
            || string(row, "method")? != "btree"
            || !row.get("expressions").is_some_and(|v| v.is_null())
            || oid(row, "key_count")? as usize != names(row, "columns")?.len()
            || oid(row, "attribute_count")? != oid(row, "key_count")?
        {
            return Err(deny("inspection_original_index"));
        }
    }
    type ConstraintKey = (String, String, Vec<String>, String, Vec<String>);
    let key = |table: &str, kind: &str, columns: Vec<&str>, target: &str, refs: Vec<&str>| {
        let mut columns: Vec<String> = columns.into_iter().map(str::to_owned).collect();
        if kind == "c" {
            columns.sort();
        }
        (
            table.to_owned(),
            kind.to_owned(),
            columns,
            target.to_owned(),
            refs.into_iter().map(str::to_owned).collect::<Vec<_>>(),
        )
    };
    let mut expected: BTreeMap<ConstraintKey, usize> = BTreeMap::new();
    for spec in ORIGINAL_CONSTRAINTS.iter().chain(INTERVENING_CONSTRAINTS) {
        *expected
            .entry(key(
                spec.table,
                spec.kind,
                spec.columns.to_vec(),
                spec.referenced_table,
                spec.referenced_columns.to_vec(),
            ))
            .or_default() += 1;
    }
    let mut seen_constraints = BTreeSet::new();
    let mut backing_indexes = BTreeSet::new();
    let mut foreign_keys = BTreeMap::new();
    for row in &rows["constraints"] {
        let id = oid(row, "oid")?;
        if !seen_constraints.insert(id) {
            return Err(deny("catalog_duplicate"));
        }
        if !original(row)? {
            continue;
        }
        nonempty(row, "name")?;
        nonempty(row, "definition")?;
        if !boolean(row, "validated")?
            || boolean(row, "deferrable")?
            || boolean(row, "deferred")?
            || !boolean(row, "local")?
            || oid(row, "inherit_count")? != 0
        {
            return Err(deny("inspection_original_constraint_state"));
        }
        let kind = string(row, "kind")?;
        let columns = names(row, "columns")?;
        let (target, references) = if kind == "f" {
            let target = string(row, "referenced_table")?;
            if string(row, "referenced_schema")? != "public"
                || tables.get(target) != Some(&oid(row, "referenced_relation")?)
                || string(row, "update_action")? != "a"
                || string(row, "delete_action")? != "a"
                || string(row, "match")? != "s"
            {
                return Err(deny("inspection_original_foreign_key"));
            }
            foreign_keys.insert(
                id,
                (oid(row, "relation")?, oid(row, "referenced_relation")?),
            );
            (target, names(row, "referenced_columns")?)
        } else {
            if oid(row, "referenced_relation")? != 0
                || !names(row, "referenced_columns")?.is_empty()
            {
                return Err(deny("inspection_original_constraint_binding"));
            }
            ("", Vec::new())
        };
        let observed = key(
            string(row, "table")?,
            kind,
            columns.clone(),
            target,
            references.clone(),
        );
        match expected.get_mut(&observed) {
            Some(count) if *count > 0 => *count -= 1,
            _ => return Err(deny("inspection_original_constraint_contract")),
        }
        if ["p", "u", "f"].contains(&kind) {
            let index = indexes
                .get(&oid(row, "index")?)
                .ok_or_else(|| deny("inspection_constraint_index"))?;
            let (relation, keys) = if kind == "f" {
                (oid(row, "referenced_relation")?, references)
            } else {
                (oid(row, "relation")?, columns)
            };
            if oid(index, "relation")? != relation
                || names(index, "columns")? != keys
                || !boolean(index, "unique")?
                || !index.get("predicate").is_some_and(|v| v.is_null())
                || (kind != "f" && boolean(index, "primary")? != (kind == "p"))
            {
                return Err(deny("inspection_constraint_index"));
            }
            if kind != "f" && !backing_indexes.insert(oid(row, "index")?) {
                return Err(deny("inspection_constraint_index"));
            }
        } else if kind == "c" {
            nonempty(row, "expression")?;
            if oid(row, "index")? != 0 {
                return Err(deny("inspection_check_index"));
            }
        }
    }
    if expected.values().any(|count| *count != 0) {
        return Err(deny("inspection_original_constraint_missing"));
    }
    let mut explicit = BTreeSet::new();
    for row in indexes.values() {
        if !original(row)? || backing_indexes.contains(&oid(row, "oid")?) {
            continue;
        }
        let spec = ORIGINAL_INDEXES
            .iter()
            .chain(INTERVENING_INDEXES)
            .find(|s| {
                s.table == string(row, "table").unwrap_or("")
                    && s.name == string(row, "name").unwrap_or("")
            })
            .ok_or_else(|| deny("inspection_original_index_contract"))?;
        let partial = row
            .get("predicate")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
        if !explicit.insert((spec.table, spec.name))
            || names(row, "columns")? != spec.columns
            || boolean(row, "unique")? != spec.unique
            || boolean(row, "primary")?
            || partial != spec.partial
            || (!spec.partial && !row.get("predicate").is_some_and(|v| v.is_null()))
        {
            return Err(deny("inspection_original_index_contract"));
        }
    }
    if explicit.len() != ORIGINAL_INDEXES.len() + INTERVENING_INDEXES.len() {
        return Err(deny("inspection_original_index_missing"));
    }
    let mut triggers = BTreeSet::new();
    let mut trigger_ids = BTreeSet::new();
    let mut fk_triggers: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for row in &rows["triggers"] {
        if !trigger_ids.insert(oid(row, "oid")?) {
            return Err(deny("catalog_duplicate"));
        }
        if !original(row)? {
            continue;
        }
        nonempty(row, "definition")?;
        if string(row, "enabled")? != "O" {
            return Err(deny("inspection_original_trigger_disabled"));
        }
        if !row.get("qualification").is_some_and(|v| v.is_null())
            || string(row, "arguments")? != ""
            || string(row, "columns")? != ""
            || boolean(row, "deferrable")?
            || boolean(row, "initially_deferred")?
            || !row.get("old_transition").is_some_and(|v| v.is_null())
            || !row.get("new_transition").is_some_and(|v| v.is_null())
        {
            return Err(deny("inspection_original_trigger_scope"));
        }
        if boolean(row, "internal")? {
            let constraint = oid(row, "constraint")?;
            let (child, parent) = foreign_keys
                .get(&constraint)
                .ok_or_else(|| deny("inspection_original_fk_trigger"))?;
            let function = string(row, "function_name")?;
            let (relation, kind) = match function {
                "RI_FKey_check_ins" => (*child, 5),
                "RI_FKey_check_upd" => (*child, 17),
                "RI_FKey_noaction_del" => (*parent, 9),
                "RI_FKey_noaction_upd" => (*parent, 17),
                _ => return Err(deny("inspection_original_fk_trigger")),
            };
            if string(row, "function_schema")? != "pg_catalog"
                || oid(row, "relation")? != relation
                || oid(row, "type")? != kind
                || !fk_triggers
                    .entry(constraint)
                    .or_default()
                    .insert(function.to_owned())
            {
                return Err(deny("inspection_original_fk_trigger"));
            }
            continue;
        }
        let spec = ORIGINAL_TRIGGERS
            .iter()
            .chain(INTERVENING_TRIGGERS)
            .find(|s| {
                s.table == string(row, "table").unwrap_or("")
                    && s.name == string(row, "name").unwrap_or("")
            })
            .ok_or_else(|| deny("inspection_original_trigger_contract"))?;
        if !triggers.insert((spec.table, spec.name))
            || oid(row, "constraint")? != 0
            || oid(row, "type")? != spec.kind
            || string(row, "function_schema")? != "public"
            || string(row, "function_name")? != spec.function
        {
            return Err(deny("inspection_original_trigger_contract"));
        }
        let functions: Vec<_> = rows["functions"]
            .iter()
            .filter(|f| oid(f, "oid").ok() == oid(row, "function").ok())
            .collect();
        if functions.len() != 1
            || string(functions[0], "schema")? != "public"
            || string(functions[0], "name")? != spec.function
            || string(functions[0], "arguments")? != ""
            || boolean(functions[0], "security_definer")?
            || ORIGINAL_FUNCTION_BODIES
                .iter()
                .chain(INTERVENING_FUNCTION_BODIES)
                .find(|(name, _)| *name == spec.function)
                .map(|(_, digest)| *digest)
                != Some(string(functions[0], "body_sha256")?)
        {
            return Err(deny("inspection_original_trigger_function"));
        }
    }
    if triggers.len() != ORIGINAL_TRIGGERS.len() + INTERVENING_TRIGGERS.len()
        || foreign_keys
            .keys()
            .any(|id| fk_triggers.get(id).map_or(0, BTreeSet::len) != 4)
    {
        return Err(deny("inspection_original_trigger_missing"));
    }
    Ok(())
}

// Original enforcement contracts from migrations 0001..0005 remain unchanged.
// Separate intervening contracts bind 0006..0008; migration 0009
// only adds the isolated role/view surface. Exact rendered definitions, ACLs,
// function bodies and all raw catalog state stay in the signed catalog digest;
// these structural contracts additionally reject missing/disabled enforcement.
struct ConstraintSpec {
    table: &'static str,
    kind: &'static str,
    columns: &'static [&'static str],
    referenced_table: &'static str,
    referenced_columns: &'static [&'static str],
}
const ORIGINAL_CONSTRAINTS: &[ConstraintSpec] = &[
    ConstraintSpec {
        table: "provider_control",
        kind: "p",
        columns: &["singleton"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "provider_control",
        kind: "c",
        columns: &["singleton"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "provider_control",
        kind: "c",
        columns: &["recovery_epoch"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "provider_control",
        kind: "c",
        columns: &["activation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "consumer_registry",
        kind: "p",
        columns: &["consumer_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "consumer_registry",
        kind: "c",
        columns: &["consumer_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "consumer_registry",
        kind: "c",
        columns: &["revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "consumer_registry",
        kind: "c",
        columns: &["registration_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "resource_replays",
        kind: "c",
        columns: &["event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "resource_replays",
        kind: "p",
        columns: &["scope", "event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "assertion_replays",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "assertion_replays",
        kind: "c",
        columns: &["jti"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "assertion_replays",
        kind: "p",
        columns: &["consumer_id", "issuer", "jti"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollment_challenges",
        kind: "p",
        columns: &["enrollment_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollment_challenges",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "enrollment_challenges",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollment_challenges",
        kind: "c",
        columns: &["expires_at", "issued_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollment_challenges",
        kind: "u",
        columns: &["consumer_id", "enrollment_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "p",
        columns: &["enrollment_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "c",
        columns: &["native_key"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "c",
        columns: &["revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "c",
        columns: &["authority_epoch"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "c",
        columns: &["proof_event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "c",
        columns: &["active", "key_retired"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollments",
        kind: "u",
        columns: &["consumer_id", "enrollment_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "enrollment_history",
        kind: "f",
        columns: &["enrollment_id"],
        referenced_table: "enrollments",
        referenced_columns: &["enrollment_id"],
    },
    ConstraintSpec {
        table: "enrollment_history",
        kind: "p",
        columns: &["enrollment_id", "revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "commands",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "commands",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "commands",
        kind: "p",
        columns: &["consumer_id", "operation", "intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "p",
        columns: &["consumer_id", "root_task_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "u",
        columns: &["consumer_id", "root_intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "f",
        columns: &["consumer_id", "enrollment_id"],
        referenced_table: "enrollments",
        referenced_columns: &["consumer_id", "enrollment_id"],
    },
    ConstraintSpec {
        table: "task_roots",
        kind: "c",
        columns: &["created_at", "expires_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_members",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_members",
        kind: "p",
        columns: &["consumer_id", "task_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "task_members",
        kind: "f",
        columns: &["consumer_id", "root_task_id"],
        referenced_table: "task_roots",
        referenced_columns: &["consumer_id", "root_task_id"],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "p",
        columns: &["attempt_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["generation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["slot_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["request_bytes"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["state"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "c",
        columns: &["result_ref", "state"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "u",
        columns: &["consumer_id", "effect_owner", "effect_intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "f",
        columns: &["consumer_id", "root_task_id"],
        referenced_table: "task_roots",
        referenced_columns: &["consumer_id", "root_task_id"],
    },
    ConstraintSpec {
        table: "attempts",
        kind: "f",
        columns: &["consumer_id", "task_id"],
        referenced_table: "task_members",
        referenced_columns: &["consumer_id", "task_id"],
    },
    ConstraintSpec {
        table: "publications",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "publications",
        kind: "u",
        columns: &["publication_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publications",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publications",
        kind: "c",
        columns: &["state"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publications",
        kind: "p",
        columns: &["consumer_id", "intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publications",
        kind: "u",
        columns: &["consumer_id", "release_ref"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publications",
        kind: "f",
        columns: &["consumer_id", "enrollment_id"],
        referenced_table: "enrollments",
        referenced_columns: &["consumer_id", "enrollment_id"],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "p",
        columns: &["reservation_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "c",
        columns: &["generation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "u",
        columns: &["consumer_id", "intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "f",
        columns: &["consumer_id", "root_task_id"],
        referenced_table: "task_roots",
        referenced_columns: &["consumer_id", "root_task_id"],
    },
    ConstraintSpec {
        table: "model_reservations",
        kind: "f",
        columns: &["consumer_id", "task_id"],
        referenced_table: "task_members",
        referenced_columns: &["consumer_id", "task_id"],
    },
    ConstraintSpec {
        table: "admission_evidence",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "admission_evidence",
        kind: "c",
        columns: &["request_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "admission_evidence",
        kind: "c",
        columns: &["native_authorization"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "admission_evidence",
        kind: "c",
        columns: &["invocation_jws"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "admission_evidence",
        kind: "p",
        columns: &["consumer_id", "issuer", "jti"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "registration_history",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "registration_history",
        kind: "p",
        columns: &["consumer_id", "revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_counters",
        kind: "p",
        columns: &["consumer_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_counters",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "observation_counters",
        kind: "c",
        columns: &["next_sequence"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_counters",
        kind: "c",
        columns: &["next_sequence", "retained_after"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observations",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "observations",
        kind: "c",
        columns: &["sequence"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observations",
        kind: "p",
        columns: &["consumer_id", "sequence"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_offsets",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "observation_offsets",
        kind: "c",
        columns: &["acknowledged"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_offsets",
        kind: "p",
        columns: &[
            "consumer_id",
            "module_id",
            "context_domain",
            "recovery_epoch",
        ],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_receipts",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "observation_receipts",
        kind: "c",
        columns: &["cursor_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_receipts",
        kind: "p",
        columns: &["consumer_id", "cursor_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_receipts",
        kind: "u",
        columns: &["consumer_id", "durable_receipt_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_keys",
        kind: "p",
        columns: &["key_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_keys",
        kind: "c",
        columns: &["secret"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "p",
        columns: &["source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "c",
        columns: &["event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "f",
        columns: &["enrollment_id"],
        referenced_table: "enrollments",
        referenced_columns: &["enrollment_id"],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "c",
        columns: &["intake_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "c",
        columns: &["event_bytes"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "c",
        columns: &["event_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "u",
        columns: &["consumer_id", "community_id", "event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_inputs",
        kind: "u",
        columns: &["consumer_id", "source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "intake_registrations",
        kind: "p",
        columns: &["consumer_id", "source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "intake_registrations",
        kind: "u",
        columns: &["consumer_id", "durable_receipt_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "intake_registrations",
        kind: "f",
        columns: &["consumer_id", "source_id"],
        referenced_table: "native_inputs",
        referenced_columns: &["consumer_id", "source_id"],
    },
    ConstraintSpec {
        table: "publication_scopes",
        kind: "p",
        columns: &["publication_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_scopes",
        kind: "f",
        columns: &["publication_id"],
        referenced_table: "publications",
        referenced_columns: &["publication_id"],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "p",
        columns: &["publication_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "f",
        columns: &["publication_id"],
        referenced_table: "publications",
        referenced_columns: &["publication_id"],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "u",
        columns: &["native_event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "c",
        columns: &["native_event_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "c",
        columns: &["signed_event"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "c",
        columns: &["event_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "publication_deliveries",
        kind: "c",
        columns: &["state"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshots",
        kind: "p",
        columns: &["snapshot_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshots",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "observation_snapshots",
        kind: "c",
        columns: &["high_water"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshot_entries",
        kind: "f",
        columns: &["snapshot_id"],
        referenced_table: "observation_snapshots",
        referenced_columns: &["snapshot_id"],
    },
    ConstraintSpec {
        table: "observation_snapshot_entries",
        kind: "c",
        columns: &["ordinal"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshot_entries",
        kind: "p",
        columns: &["snapshot_id", "ordinal"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshot_cursors",
        kind: "p",
        columns: &["cursor_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshot_cursors",
        kind: "f",
        columns: &["snapshot_id"],
        referenced_table: "observation_snapshots",
        referenced_columns: &["snapshot_id"],
    },
    ConstraintSpec {
        table: "observation_snapshot_cursors",
        kind: "c",
        columns: &["through"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "observation_snapshot_cursors",
        kind: "u",
        columns: &["snapshot_id", "through"],
        referenced_table: "",
        referenced_columns: &[],
    },
];
const ORIGINAL_FUNCTION_BODIES: &[(&str, &str)] = &[
    (
        "deny_history_mutation",
        "be9219cc66b61dc3f9a7432995dcc43b32fd0390d2dabfaaa883abe9d27876f5",
    ),
    (
        "freeze_root_identity",
        "fc095520cdaf67564cd146eaa4004a20b72f19dd273c059f8612e2cfa26cccf3",
    ),
    (
        "freeze_attempt_identity",
        "1dfaad76c6841f5157ac51ec9627ded5f199830f0633fad8ab03d065533a2ad9",
    ),
    (
        "freeze_binding_identity",
        "e43c4b97194bc4b503a82ca87fb925cb810bc1a4730c4ed1660fd141a8f77f78",
    ),
    (
        "freeze_publication_delivery",
        "821bd71017dab7aeca216b1139cb5b7d20cd00a6dd2c4075f3b23a8cac02c26a",
    ),
];

struct TriggerSpec {
    table: &'static str,
    name: &'static str,
    function: &'static str,
    kind: u32,
}
const ORIGINAL_TRIGGERS: &[TriggerSpec] = &[
    TriggerSpec {
        table: "enrollment_history",
        name: "immutable_enrollment_history",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "commands",
        name: "immutable_command_history",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "task_members",
        name: "immutable_task_members",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "publications",
        name: "immutable_publications",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "task_roots",
        name: "immutable_root_identity",
        function: "freeze_root_identity",
        kind: 19,
    },
    TriggerSpec {
        table: "attempts",
        name: "immutable_attempt_identity",
        function: "freeze_attempt_identity",
        kind: 19,
    },
    TriggerSpec {
        table: "enrollments",
        name: "immutable_binding_identity",
        function: "freeze_binding_identity",
        kind: 19,
    },
    TriggerSpec {
        table: "model_reservations",
        name: "immutable_model_reservation",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "task_roots",
        name: "no_delete_roots",
        function: "deny_history_mutation",
        kind: 11,
    },
    TriggerSpec {
        table: "attempts",
        name: "no_delete_attempts",
        function: "deny_history_mutation",
        kind: 11,
    },
    TriggerSpec {
        table: "enrollments",
        name: "no_delete_bindings",
        function: "deny_history_mutation",
        kind: 11,
    },
    TriggerSpec {
        table: "admission_evidence",
        name: "immutable_admission_evidence",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "registration_history",
        name: "immutable_registration_history",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "observations",
        name: "immutable_observations",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "observation_receipts",
        name: "immutable_observation_receipts",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "native_inputs",
        name: "immutable_native_inputs",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "intake_registrations",
        name: "immutable_intake_registrations",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "publication_scopes",
        name: "immutable_publication_scope",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "publication_deliveries",
        name: "immutable_publication_delivery",
        function: "freeze_publication_delivery",
        kind: 19,
    },
    TriggerSpec {
        table: "publication_deliveries",
        name: "no_delete_publication_delivery",
        function: "deny_history_mutation",
        kind: 11,
    },
    TriggerSpec {
        table: "observation_snapshots",
        name: "immutable_observation_snapshots",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "observation_snapshot_entries",
        name: "immutable_observation_snapshot_entries",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "observation_snapshot_cursors",
        name: "immutable_observation_snapshot_cursors",
        function: "deny_history_mutation",
        kind: 27,
    },
];
struct IndexSpec {
    table: &'static str,
    name: &'static str,
    columns: &'static [&'static str],
    unique: bool,
    partial: bool,
}
const ORIGINAL_INDEXES: &[IndexSpec] = &[
    IndexSpec {
        table: "resource_replays",
        name: "resource_replays_expiry",
        columns: &["expires_at"],
        unique: false,
        partial: false,
    },
    IndexSpec {
        table: "enrollments",
        name: "one_active_principal_module",
        columns: &["consumer_id", "module_id", "issuer", "subject"],
        unique: true,
        partial: true,
    },
    IndexSpec {
        table: "enrollments",
        name: "one_active_key_module",
        columns: &["consumer_id", "module_id", "native_key"],
        unique: true,
        partial: true,
    },
    IndexSpec {
        table: "attempts",
        name: "unresolved_effect_slot",
        columns: &["consumer_id", "effect_owner", "slot_sha256"],
        unique: true,
        partial: true,
    },
    IndexSpec {
        table: "observations",
        name: "observation_scope",
        columns: &["consumer_id", "module_id", "context_domain", "sequence"],
        unique: false,
        partial: false,
    },
    IndexSpec {
        table: "observation_keys",
        name: "one_active_observation_key",
        columns: &["active"],
        unique: true,
        partial: true,
    },
];

// Enforcement-only current tables are NOT metadata exports or view-owner grants.
const INTERVENING_TABLES: &[&str] = &[
    "model_dispatches",
    "native_attachments",
    "native_attachment_leases",
];
const INTERVENING_CONSTRAINTS: &[ConstraintSpec] = &[
    ConstraintSpec {
        table: "model_dispatches",
        kind: "p",
        columns: &["reservation_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "f",
        columns: &["reservation_id"],
        referenced_table: "model_reservations",
        referenced_columns: &["reservation_id"],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "f",
        columns: &["consumer_id"],
        referenced_table: "consumer_registry",
        referenced_columns: &["consumer_id"],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "f",
        columns: &["consumer_id", "root_task_id"],
        referenced_table: "task_roots",
        referenced_columns: &["consumer_id", "root_task_id"],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "f",
        columns: &["consumer_id", "task_id"],
        referenced_table: "task_members",
        referenced_columns: &["consumer_id", "task_id"],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "c",
        columns: &["generation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "c",
        columns: &["state"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "c",
        columns: &["state", "settlement"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "c",
        columns: &["state", "settled_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "model_dispatches",
        kind: "c",
        columns: &["dispatch_deadline", "dispatched_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "p",
        columns: &["consumer_id", "source_id", "evidence_source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "f",
        columns: &["consumer_id", "source_id"],
        referenced_table: "native_inputs",
        referenced_columns: &["consumer_id", "source_id"],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["byte_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["byte_length"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["bytes", "byte_length"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["bytes", "byte_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["evidence", "byte_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["evidence", "evidence_source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachments",
        kind: "c",
        columns: &["evidence", "byte_length"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "p",
        columns: &["lease_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "u",
        columns: &["consumer_id", "operation", "intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "f",
        columns: &["enrollment_id"],
        referenced_table: "enrollments",
        referenced_columns: &["enrollment_id"],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "f",
        columns: &["consumer_id", "source_id", "evidence_source_id"],
        referenced_table: "native_attachments",
        referenced_columns: &["consumer_id", "source_id", "evidence_source_id"],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["operation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["byte_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["enrollment_revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["binding_epoch"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["native_key"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "byte_sha256"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "evidence_source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "source_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "enrollment_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "enrollment_revision"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["request", "expires_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["claims", "consumer_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["claims", "operation"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["claims", "intent_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["claims", "module_id"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["claims", "context_domain"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["expires_at", "claims"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["expires_at", "claims"],
        referenced_table: "",
        referenced_columns: &[],
    },
    ConstraintSpec {
        table: "native_attachment_leases",
        kind: "c",
        columns: &["expires_at", "created_at"],
        referenced_table: "",
        referenced_columns: &[],
    },
];
const INTERVENING_TRIGGERS: &[TriggerSpec] = &[
    TriggerSpec {
        table: "model_dispatches",
        name: "immutable_model_dispatch",
        function: "freeze_model_dispatch",
        kind: 19,
    },
    TriggerSpec {
        table: "model_dispatches",
        name: "no_delete_model_dispatch",
        function: "deny_history_mutation",
        kind: 11,
    },
    TriggerSpec {
        table: "native_attachments",
        name: "immutable_native_attachments",
        function: "deny_history_mutation",
        kind: 27,
    },
    TriggerSpec {
        table: "native_attachment_leases",
        name: "immutable_native_attachment_leases",
        function: "deny_history_mutation",
        kind: 27,
    },
];
const INTERVENING_INDEXES: &[IndexSpec] = &[
    IndexSpec {
        table: "model_dispatches",
        name: "unresolved_model_dispatch",
        columns: &["consumer_id", "root_task_id"],
        unique: false,
        partial: true,
    },
    IndexSpec {
        table: "native_attachment_leases",
        name: "native_attachment_lease_lookup",
        columns: &["byte_sha256", "native_key", "expires_at"],
        unique: false,
        partial: false,
    },
];
const INTERVENING_FUNCTION_BODIES: &[(&str, &str)] = &[(
    "freeze_model_dispatch",
    "fd06c18e650ac887d53dd6b8f08bd0f1019657ccc9907812a563b1113f111b30",
)];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchemaManifest {
    v: u8,
    source_revision: String,
    generation: u64,
    database_oid: u32,
    migration_sha256: std::collections::BTreeMap<String, String>,
    catalog_sha256: String,
    observed_us: i64,
    expires_us: i64,
}
impl SchemaManifest {
    pub(crate) fn authenticate(
        &self,
        auth: &super::authority::Authenticated,
        budget: &mut super::clock::Budget,
    ) -> Result<()> {
        let expected = super::relations::migration_pins();
        if self.migration_sha256 != expected {
            return Err(deny("inspection_installed_migrations"));
        }
        llull_buzz_wire::hash(&self.catalog_sha256)
            .map_err(|_| deny("inspection_catalog_digest"))?;
        // Source hashing is complete before the terminal live sample. Future
        // consumers only inspect captured authenticated immutable scalar bounds.
        let terminal = budget.sample(super::clock::now())?;
        auth.current(terminal)?;
        self.current(auth, terminal)
    }
    pub(crate) fn current(&self, auth: &super::authority::Authenticated, now: i64) -> Result<()> {
        if self.v != 1
            || self.source_revision != auth.source_revision()
            || self.generation != auth.generation()
            || self.database_oid != auth.profile().database.database_oid
            || self.observed_us < 0
            || self.observed_us > now
            || self.expires_us <= now
        {
            return Err(deny("inspection_schema_manifest"));
        }
        Ok(())
    }
    pub(crate) fn expiry(&self) -> i64 {
        self.expires_us
    }
}
/// Deterministic length-framed raw server catalog bytes. No numeric parsing or
/// canonical reserialization can change the manifest's observed original bytes.
fn verify_catalog_current(
    raw: &std::collections::BTreeMap<String, Vec<Vec<u8>>>,
    expected: &Database,
    expected_digest: &str,
    budget: &mut super::clock::Budget,
) -> Result<String> {
    if raw.len() != QUERIES.len() || QUERIES.iter().any(|q| !raw.contains_key(q.name)) {
        return Err(deny("catalog_scope"));
    }
    let mut custody = Vec::new();
    let mut decoded = std::collections::BTreeMap::new();
    for query in QUERIES {
        custody.extend_from_slice(&(query.name.len() as u64).to_be_bytes());
        custody.extend_from_slice(query.name.as_bytes());
        custody.extend_from_slice(&(raw[query.name].len() as u64).to_be_bytes());
        let mut rows = Vec::new();
        let mut prior: Option<&[u8]> = None;
        for bytes in &raw[query.name] {
            super::json::validate_raw(bytes)?;
            if prior.is_some_and(|p| p >= bytes.as_slice()) {
                return Err(deny("catalog_order_or_duplicate"));
            }
            prior = Some(bytes);
            custody.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            custody.extend_from_slice(bytes);
            rows.push(serde_json::from_slice(bytes).map_err(|_| deny("catalog_shape"))?);
            budget.sample(super::clock::now())?;
        }
        decoded.insert(query.name.to_owned(), rows);
    }
    let roles = raw["roles"]
        .iter()
        .map(|bytes| super::json::decode::<Role>(bytes))
        .collect::<Result<Vec<_>>>()?;
    let memberships = raw["memberships"]
        .iter()
        .map(|bytes| super::json::decode::<Membership>(bytes))
        .collect::<Result<Vec<_>>>()?;
    verify_roles(&roles, &memberships, expected)?;
    verify_effective_capabilities(&decoded, expected)?;
    let digest = llull_buzz_wire::sha256(&custody);
    if digest != expected_digest {
        return Err(deny("inspection_current_schema"));
    }
    budget.sample(super::clock::now())?;
    Ok(digest)
}

pub(crate) fn verify_retained(
    raw: &std::collections::BTreeMap<String, Vec<Vec<u8>>>,
    auth: &super::authority::Authenticated,
    manifest: &SchemaManifest,
    budget: &mut super::clock::Budget,
) -> Result<String> {
    let digest = verify_catalog_current(
        raw,
        &auth.profile().database,
        &manifest.catalog_sha256,
        budget,
    )?;
    let terminal = budget.sample(super::clock::now())?;
    auth.current(terminal)?;
    manifest.current(auth, terminal)?;
    Ok(digest)
}

/// Synthetic transport data for authored source controls only. Definitions are
/// deliberately labelled synthetic; this is not a claimed installed catalog.
#[cfg(test)]
pub(super) fn synthetic_catalog(db: &Database) -> std::collections::BTreeMap<String, Vec<Vec<u8>>> {
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    let mut rows: BTreeMap<String, Vec<Value>> = QUERIES
        .iter()
        .map(|q| (q.name.into(), Vec::new()))
        .collect();
    rows.get_mut("database").unwrap().push(json!({"oid":db.database_oid,"name":db.database,"owner":999,"acl":"{ordinary_runtime=CTc/fixture_admin}","create":false,"temporary":false,"owner_create":false,"owner_temporary":false}));
    for (oid, name, login) in [
        (db.inspector_oid, INSPECTOR, true),
        (db.view_owner_oid, VIEW_OWNER, false),
        (999, "fixture_admin", true),
    ] {
        rows.get_mut("roles").unwrap().push(json!({"oid":oid,"name":name,"super":false,"createdb":false,"createrole":false,"inherit":false,"login":login,"replication":false,"bypassrls":false}));
    }
    rows.get_mut("schemas").unwrap().extend([
        json!({"oid":900,"name":"public","owner":999,"acl":null,"create":false,"usage":true}),
        json!({"oid":901,"name":"buzz_inspection","owner":db.view_owner_oid,"acl":"synthetic","create":false,"usage":true}),
    ]);
    let mut tables = BTreeMap::new();
    for (i, relation) in super::relations::RELATIONS.iter().enumerate() {
        let oid = 1000 + i as u32;
        tables.insert(relation.name, oid);
        for (id, schema, name, kind, owner, select, definition, options) in [
            (
                oid,
                "public",
                relation.name.to_owned(),
                "r",
                999,
                false,
                Value::Null,
                Value::Null,
            ),
            (
                10000 + i as u32,
                "buzz_inspection",
                format!("v_{}", relation.name),
                "v",
                db.view_owner_oid,
                true,
                json!(db.view_definition_sha256[relation.name]),
                json!(["security_barrier=true"]),
            ),
        ] {
            rows.get_mut("relations").unwrap().push(json!({"oid":id,"schema":schema,"name":name,"kind":kind,"owner":owner,"select":select,"insert":false,"update":false,"delete":false,"truncate":false,"references":false,"trigger":false,"rls":false,"force_rls":false,"acl":null,"definition":definition,"options":options}));
        }
        for (number, name, type_oid) in [
            (1, "row_sha256", 25),
            (2, "row_key", 3802),
            (3, "metadata", 3802),
        ] {
            rows.get_mut("columns").unwrap().push(json!({"relation":10000+i as u32,"number":number,"name":name,"type":type_oid,"select":true,"insert":false,"update":false,"references":false}));
        }
    }
    for (i, name) in INTERVENING_TABLES.iter().enumerate() {
        let id = 1100 + i as u32;
        tables.insert(*name, id);
        rows.get_mut("relations").unwrap().push(json!({"oid":id,"schema":"public","name":name,"kind":"r","owner":999,"select":false,"insert":false,"update":false,"delete":false,"truncate":false,"references":false,"trigger":false,"rls":false,"force_rls":false,"acl":null,"definition":null,"options":null}));
    }
    let index_row = |id, table: &str, name: &str, columns: &[&str], unique, primary, partial| json!({"oid":id,"relation":tables[table],"schema":"public","table":table,"name":name,"owner":999,"method":"btree","unique":unique,"primary":primary,"exclusion":false,"immediate":true,"valid":true,"ready":true,"live":true,"nulls_not_distinct":false,"key_count":columns.len(),"attribute_count":columns.len(),"columns":columns,"predicate":if partial {json!("synthetic original predicate")}else{Value::Null},"expressions":null,"definition":format!("synthetic index {table}.{name}"),"catalog":{}});
    let mut key_indexes = BTreeMap::new();
    for (i, spec) in ORIGINAL_CONSTRAINTS
        .iter()
        .chain(INTERVENING_CONSTRAINTS)
        .enumerate()
    {
        if ["p", "u"].contains(&spec.kind) {
            let id = 2000 + i as u32;
            key_indexes.insert((spec.table, spec.columns.to_vec()), id);
            rows.get_mut("indexes").unwrap().push(index_row(
                id,
                spec.table,
                &format!("synthetic_key_{i}"),
                spec.columns,
                true,
                spec.kind == "p",
                false,
            ));
        }
    }
    for (i, spec) in ORIGINAL_INDEXES
        .iter()
        .chain(INTERVENING_INDEXES)
        .enumerate()
    {
        rows.get_mut("indexes").unwrap().push(index_row(
            4000 + i as u32,
            spec.table,
            spec.name,
            spec.columns,
            spec.unique,
            false,
            spec.partial,
        ));
    }
    for (i, spec) in ORIGINAL_CONSTRAINTS
        .iter()
        .chain(INTERVENING_CONSTRAINTS)
        .enumerate()
    {
        let id = 3000 + i as u32;
        let index = match spec.kind {
            "p" | "u" => 2000 + i as u32,
            "f" => key_indexes[&(spec.referenced_table, spec.referenced_columns.to_vec())],
            _ => 0,
        };
        let referenced = if spec.kind == "f" {
            tables[spec.referenced_table]
        } else {
            0
        };
        rows.get_mut("constraints").unwrap().push(json!({"oid":id,"relation":tables[spec.table],"schema":"public","table":spec.table,"name":format!("synthetic_constraint_{i}"),"kind":spec.kind,"columns":spec.columns,"referenced_relation":referenced,"referenced_schema":if spec.kind=="f" {json!("public")}else{Value::Null},"referenced_table":if spec.kind=="f" {json!(spec.referenced_table)}else{Value::Null},"referenced_columns":spec.referenced_columns,"index":index,"validated":true,"deferrable":false,"deferred":false,"local":true,"inherit_count":0,"update_action":if spec.kind=="f"{"a"}else{" "},"delete_action":if spec.kind=="f"{"a"}else{" "},"match":if spec.kind=="f"{"s"}else{" "},"definition":format!("synthetic original constraint {i}"),"expression":if spec.kind=="c" {json!(format!("synthetic check {i}"))}else{Value::Null},"catalog":{}}));
        if spec.kind == "f" {
            for (j, (function, table, kind)) in [
                ("RI_FKey_check_ins", spec.table, 5),
                ("RI_FKey_check_upd", spec.table, 17),
                ("RI_FKey_noaction_del", spec.referenced_table, 9),
                ("RI_FKey_noaction_upd", spec.referenced_table, 17),
            ]
            .into_iter()
            .enumerate()
            {
                rows.get_mut("triggers").unwrap().push(json!({"oid":6000+(i*4+j) as u32,"relation":tables[table],"schema":"public","table":table,"name":format!("synthetic_RI_{i}_{j}"),"function":9000+j,"function_schema":"pg_catalog","function_name":function,"enabled":"O","type":kind,"internal":true,"constraint":id,"qualification":null,"arguments":"","columns":"","deferrable":false,"initially_deferred":false,"old_transition":null,"new_transition":null,"definition":"synthetic FK trigger","catalog":{}}));
            }
        }
    }
    let functions: BTreeSet<_> = ORIGINAL_TRIGGERS
        .iter()
        .chain(INTERVENING_TRIGGERS)
        .map(|s| s.function)
        .collect();
    let functions: BTreeMap<_, _> = functions
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, 8000 + i as u32))
        .collect();
    for (name, oid) in &functions {
        rows.get_mut("functions").unwrap().push(json!({"oid":oid,"schema":"public","name":name,"arguments":"","owner":999,"security_definer":false,"config":null,"acl":"synthetic","execute":false,"definition_sha256":llull_buzz_wire::sha256(name.as_bytes()),"body_sha256":ORIGINAL_FUNCTION_BODIES.iter().chain(INTERVENING_FUNCTION_BODIES).find(|(n,_)|n==name).unwrap().1}));
    }
    for (i, spec) in ORIGINAL_TRIGGERS
        .iter()
        .chain(INTERVENING_TRIGGERS)
        .enumerate()
    {
        rows.get_mut("triggers").unwrap().push(json!({"oid":5000+i as u32,"relation":tables[spec.table],"schema":"public","table":spec.table,"name":spec.name,"function":functions[spec.function],"function_schema":"public","function_name":spec.function,"enabled":"O","type":spec.kind,"internal":false,"constraint":0,"qualification":null,"arguments":"","columns":"","deferrable":false,"initially_deferred":false,"old_transition":null,"new_transition":null,"definition":format!("synthetic original trigger {}",spec.name),"catalog":{}}));
    }
    rows.into_iter()
        .map(|(name, values)| {
            let mut raw: Vec<_> = values
                .iter()
                .map(|v| serde_json::to_vec(v).unwrap())
                .collect();
            raw.sort();
            (name, raw)
        })
        .collect()
}
#[cfg(test)]
pub(super) fn synthetic_catalog_digest(
    raw: &std::collections::BTreeMap<String, Vec<Vec<u8>>>,
) -> String {
    let mut framed = Vec::new();
    for q in QUERIES {
        framed.extend_from_slice(&(q.name.len() as u64).to_be_bytes());
        framed.extend_from_slice(q.name.as_bytes());
        framed.extend_from_slice(&(raw[q.name].len() as u64).to_be_bytes());
        for bytes in &raw[q.name] {
            framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            framed.extend_from_slice(bytes);
        }
    }
    llull_buzz_wire::sha256(&framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn database() -> Database {
        Database {
            host: "fixture.invalid".into(),
            port: 5432,
            database: "fixture".into(),
            database_oid: 77,
            inspector_oid: 101,
            view_owner_oid: 102,
            server_address: "127.0.0.1".into(),
            server_version_num: 160000,
            ssl_root_sha256: "a".repeat(64),
            schema_manifest_sha256: "b".repeat(64),
            view_definition_sha256: super::super::relations::RELATIONS
                .iter()
                .map(|r| (r.name.into(), "c".repeat(64)))
                .collect(),
        }
    }
    fn role(oid: u32, name: &str, login: bool) -> Role {
        Role {
            oid,
            name: name.into(),
            superuser: false,
            createdb: false,
            createrole: false,
            inherit: false,
            login,
            replication: false,
            bypassrls: false,
        }
    }
    #[test]
    fn actual_role_verifier_accepts_dedicated_pair_then_refuses_inherited_or_owner_escalation() {
        let db = database();
        let mut roles = vec![
            role(101, INSPECTOR, true),
            role(102, VIEW_OWNER, false),
            role(103, "ordinary_runtime", true),
        ];
        verify_roles(&roles, &[], &db).unwrap();
        for membership in [
            Membership {
                role: 103,
                member: 101,
                grantor: 103,
                admin: false,
            },
            Membership {
                role: 102,
                member: 103,
                grantor: 103,
                admin: false,
            },
        ] {
            assert!(verify_roles(&roles, &[membership], &db).is_err());
        }
        roles[0].superuser = true;
        assert!(verify_roles(&roles, &[], &db).is_err());
    }
    #[test]
    fn actual_session_verifier_requires_original_login_physical_endpoint_and_rr_readonly() {
        let db = database();
        let raw = serde_json::json!({"current_user":INSPECTOR,"session_user":INSPECTOR,"database":"fixture","database_oid":77,"address":"127.0.0.1","port":5432,"version":160000,"search_path":"pg_catalog, buzz_inspection","read_only":"on","isolation":"repeatable read","create":false,"temporary":false,"snapshot":"1:2:"});
        let session: Session = serde_json::from_value(raw.clone()).unwrap();
        session.verify(&db).unwrap();
        for (name, value) in [
            ("session_user", serde_json::json!("operator")),
            ("database_oid", serde_json::json!(78)),
            ("create", serde_json::json!(true)),
            ("temporary", serde_json::json!(true)),
            (
                "search_path",
                serde_json::json!("buzz_inspection, pg_catalog"),
            ),
            (
                "search_path",
                serde_json::json!("pg_catalog, buzz_inspection, public"),
            ),
            (
                "search_path",
                serde_json::json!("$user, pg_catalog, buzz_inspection"),
            ),
            ("read_only", serde_json::json!("off")),
            ("isolation", serde_json::json!("read committed")),
        ] {
            let mut changed = raw.clone();
            changed[name] = value;
            let session: Session = serde_json::from_value(changed).unwrap();
            assert!(session.verify(&db).is_err());
        }
    }
    #[test]
    fn current_catalog_scope_does_not_hide_ordinary_pgx_schemas_or_public_capabilities() {
        for query in QUERIES {
            assert!(!query.sql.contains("LIKE 'pg_%'"));
        }
        for name in ["functions", "columns", "schemas", "relations", "sequences"] {
            let query = QUERIES.iter().find(|q| q.name == name).unwrap();
            assert!(query.sql.contains("left("));
        }
        assert!(QUERIES
            .iter()
            .find(|q| q.name == "functions")
            .unwrap()
            .sql
            .contains("has_function_privilege(current_user"));
        assert!(QUERIES
            .iter()
            .find(|q| q.name == "memberships")
            .unwrap()
            .sql
            .contains("'grantor',grantor"));
    }
    fn verify_source(
        raw: &std::collections::BTreeMap<String, Vec<Vec<u8>>>,
        db: &Database,
        digest: &str,
    ) -> Result<String> {
        let now = super::super::clock::now();
        let mut budget = super::super::clock::Budget::new(now, now + 20_000_000).unwrap();
        verify_catalog_current(raw, db, digest, &mut budget)
    }
    fn change_row(
        raw: &mut std::collections::BTreeMap<String, Vec<Vec<u8>>>,
        category: &str,
        select: impl Fn(&serde_json::Value) -> bool,
        change: impl FnOnce(&mut serde_json::Value),
    ) {
        let rows = raw.get_mut(category).unwrap();
        let index = rows
            .iter()
            .position(|b| select(&serde_json::from_slice(b).unwrap()))
            .expect("required actual fixture row missing");
        let mut value = serde_json::from_slice(&rows[index]).unwrap();
        change(&mut value);
        rows[index] = serde_json::to_vec(&value).unwrap();
        rows.sort();
    }
    #[test]
    fn actual_complete_catalog_verifier_accepts_original_enforcement_and_dedicated_capabilities() {
        let db = database();
        let raw = synthetic_catalog(&db);
        assert_eq!(ORIGINAL_CONSTRAINTS.len(), 118);
        assert_eq!(ORIGINAL_TRIGGERS.len(), 23);
        assert_eq!(ORIGINAL_INDEXES.len(), 6);
        let original_keys = ORIGINAL_CONSTRAINTS
            .iter()
            .filter(|s| ["p", "u"].contains(&s.kind))
            .count();
        let added_keys = INTERVENING_CONSTRAINTS
            .iter()
            .filter(|s| ["p", "u"].contains(&s.kind))
            .count();
        assert_eq!(original_keys, 40);
        assert_eq!(original_keys + ORIGINAL_INDEXES.len(), 46);
        assert_eq!(added_keys, 4);
        assert_eq!(added_keys + INTERVENING_INDEXES.len(), 6);
        assert_eq!(raw["indexes"].len(), 46 + 6);
        assert_eq!(raw["triggers"].len(), 23 + 29 * 4 + 4 + 7 * 4);
        assert_eq!(INTERVENING_CONSTRAINTS.len(), 42);
        assert_eq!(INTERVENING_TRIGGERS.len(), 4);
        assert_eq!(INTERVENING_INDEXES.len(), 2);
        assert_eq!(
            verify_source(&raw, &db, &synthetic_catalog_digest(&raw)).unwrap(),
            synthetic_catalog_digest(&raw)
        );
    }
    #[test]
    fn current_forward_catalog_refuses_missing_or_changed_intervening_enforcement() {
        let db = database();
        let raw = synthetic_catalog(&db);
        verify_source(&raw, &db, &synthetic_catalog_digest(&raw)).unwrap();
        // Rebind each adverse digest: a self-consistent new catalog cannot bless
        // missing/disabled enforcement or selected-reader access to private data.
        for table in INTERVENING_TABLES {
            for category in ["relations", "constraints", "triggers"] {
                let mut changed = raw.clone();
                let values = changed.get_mut(category).unwrap();
                let index = values
                    .iter()
                    .position(|b| {
                        let row: serde_json::Value = serde_json::from_slice(b).unwrap();
                        row[if category == "relations" {
                            "name"
                        } else {
                            "table"
                        }] == *table
                    })
                    .unwrap();
                values.remove(index);
                assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
            }
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "relations",
                |v| v["name"] == *table,
                |v| v["select"] = serde_json::json!(true),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "triggers",
                |v| v["table"] == *table && v["internal"] == false,
                |v| v["enabled"] = serde_json::json!("D"),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        for spec in INTERVENING_CONSTRAINTS {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "constraints",
                |v| {
                    v["table"] == spec.table
                        && v["kind"] == spec.kind
                        && names(v, "columns").unwrap() == spec.columns
                },
                |v| v["validated"] = serde_json::json!(false),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        for spec in INTERVENING_INDEXES {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "indexes",
                |v| v["name"] == spec.name,
                |v| v["valid"] = serde_json::json!(false),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        for field in ["body_sha256", "execute"] {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "functions",
                |v| v["name"] == "freeze_model_dispatch",
                |v| {
                    v[field] = if field == "execute" {
                        serde_json::json!(true)
                    } else {
                        serde_json::json!("0".repeat(64))
                    }
                },
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
    }
    #[test]
    fn current_model_function_commitment_matches_unchanged_migration_body() {
        let source = include_str!("../../../../migrations/0006_model_dispatch.sql");
        let body = source
            .split_once("AS $$")
            .unwrap()
            .1
            .split_once("$$;")
            .unwrap()
            .0;
        assert_eq!(
            llull_buzz_wire::sha256(body.as_bytes()),
            INTERVENING_FUNCTION_BODIES[0].1
        );
        assert_eq!(super::super::relations::migration_pins().len(), 9);
        assert_eq!(super::super::relations::RELATIONS.len(), 27);
    }
    #[test]
    fn actual_catalog_refuses_direct_public_database_create_temp_and_dedicated_ownership() {
        let db = database();
        let raw = synthetic_catalog(&db);
        for (field, acl) in [
            ("create", "{buzz_recovery_inspector=C/fixture_admin}"),
            ("create", "{=C/fixture_admin}"),
            ("temporary", "{=T/fixture_admin}"),
            ("owner_create", "{buzz_recovery_view_owner=C/fixture_admin}"),
            (
                "owner_temporary",
                "{buzz_recovery_view_owner=T/fixture_admin}",
            ),
        ] {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "database",
                |_| true,
                |v| {
                    v[field] = serde_json::json!(true);
                    v["acl"] = serde_json::json!(acl);
                },
            );
            // Even a newly bound catalog digest cannot bless a forbidden right.
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        for owner in [db.inspector_oid, db.view_owner_oid] {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "database",
                |_| true,
                |v| v["owner"] = serde_json::json!(owner),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        let mut lawful = raw.clone();
        change_row(
            &mut lawful,
            "database",
            |_| true,
            |v| {
                v["acl"] = serde_json::json!(
                    "{ordinary_runtime=CTc/fixture_admin,another_runtime=C/fixture_admin}"
                )
            },
        );
        assert!(verify_source(&lawful, &db, &synthetic_catalog_digest(&lawful)).is_ok());
        assert!(verify_source(&lawful, &db, &synthetic_catalog_digest(&raw)).is_err());
    }
    #[test]
    fn actual_catalog_refuses_disabled_rebound_missing_user_and_foreign_key_triggers() {
        let db = database();
        let raw = synthetic_catalog(&db);
        for trigger in [
            "immutable_enrollment_history",
            "immutable_observation_snapshot_entries",
        ] {
            for (field, value) in [
                ("enabled", serde_json::json!("D")),
                ("function_name", serde_json::json!("freeze_root_identity")),
                ("type", serde_json::json!(19)),
                ("relation", serde_json::json!(0)),
                ("qualification", serde_json::json!("false")),
                ("arguments", serde_json::json!("00")),
            ] {
                let mut changed = raw.clone();
                change_row(
                    &mut changed,
                    "triggers",
                    |v| v["name"] == trigger,
                    |v| v[field] = value,
                );
                assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
            }
            let mut changed = raw.clone();
            changed.get_mut("triggers").unwrap().retain(|b| {
                serde_json::from_slice::<serde_json::Value>(b).unwrap()["name"] != trigger
            });
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        let mut changed = raw.clone();
        change_row(
            &mut changed,
            "functions",
            |v| v["name"] == "deny_history_mutation",
            |v| v["body_sha256"] = serde_json::json!("0".repeat(64)),
        );
        assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        let mut changed = raw.clone();
        change_row(
            &mut changed,
            "triggers",
            |v| v["internal"] == true,
            |v| v["enabled"] = serde_json::json!("D"),
        );
        assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        let mut changed = raw.clone();
        let position = changed["triggers"]
            .iter()
            .position(|b| {
                serde_json::from_slice::<serde_json::Value>(b).unwrap()["internal"] == true
            })
            .unwrap();
        changed.get_mut("triggers").unwrap().remove(position);
        assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
    }
    #[test]
    fn actual_catalog_refuses_missing_or_rebound_unique_foreign_key_check_and_index_contracts() {
        let db = database();
        let raw = synthetic_catalog(&db);
        for kind in ["p", "u", "f", "c"] {
            let mut changed = raw.clone();
            let position = changed["constraints"]
                .iter()
                .position(|b| {
                    serde_json::from_slice::<serde_json::Value>(b).unwrap()["kind"] == kind
                })
                .unwrap();
            changed.get_mut("constraints").unwrap().remove(position);
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "constraints",
                |v| v["kind"] == kind,
                |v| v["validated"] = serde_json::json!(false),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "constraints",
                |v| v["kind"] == kind,
                |v| v["columns"] = serde_json::json!(["wrong_binding"]),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        for field in ["valid", "ready", "live", "unique"] {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                "indexes",
                |v| v["primary"] == true,
                |v| v[field] = serde_json::json!(false),
            );
            assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
        }
        let mut changed = raw.clone();
        change_row(
            &mut changed,
            "constraints",
            |v| v["kind"] == "f",
            |v| v["delete_action"] = serde_json::json!("c"),
        );
        assert!(verify_source(&changed, &db, &synthetic_catalog_digest(&changed)).is_err());
    }
    #[test]
    fn actual_catalog_binds_check_predicate_function_and_full_catalog_definitions_to_original_digest(
    ) {
        let db = database();
        let raw = synthetic_catalog(&db);
        let digest = synthetic_catalog_digest(&raw);
        for (category, field) in [
            ("constraints", "definition"),
            ("constraints", "expression"),
            ("indexes", "predicate"),
            ("functions", "definition_sha256"),
            ("functions", "body_sha256"),
            ("triggers", "definition"),
            ("triggers", "catalog"),
        ] {
            let mut changed = raw.clone();
            change_row(
                &mut changed,
                category,
                |v| match category {
                    "constraints" => v["kind"] == "c",
                    "indexes" => v["predicate"].is_string(),
                    "triggers" => v["internal"] == false,
                    _ => true,
                },
                |v| v[field] = serde_json::json!("changed enforcing definition"),
            );
            assert!(verify_source(&changed, &db, &digest).is_err());
        }
    }

    // AUTHORED UNRUN. This invokes the actual verifier on real retained catalog
    // bytes; only an explicitly isolated administrative fixture may execute it.
    async fn native_catalog(
        sql: &mut sqlx::PgConnection,
    ) -> std::result::Result<std::collections::BTreeMap<String, Vec<Vec<u8>>>, sqlx::Error> {
        use sqlx::Row;
        let mut raw = std::collections::BTreeMap::new();
        let mut total_rows = 0u64;
        let mut total_bytes = 0u64;
        let now = super::super::clock::now();
        let mut budget = super::super::clock::Budget::new(now, now + 20_000_000).unwrap();
        for query in QUERIES {
            budget
                .sample(super::super::clock::now())
                .map_err(|_| sqlx::Error::Protocol("catalog clock refused".into()))?;
            let preflight=format!("SELECT count(*)::bigint AS rows,coalesce(sum(octet_length(raw)),0)::bigint AS bytes FROM ({}) c",query.sql);
            // query.sql is a literal from the closed QUERIES registry; no
            // native fixture data is interpolated into these catalog statements.
            let count = sqlx::query(sqlx::AssertSqlSafe(preflight))
                .fetch_one(&mut *sql)
                .await?;
            let rows = count.get::<i64, _>("rows");
            let bytes = count.get::<i64, _>("bytes");
            if rows < 0 || bytes < 0 {
                return Err(sqlx::Error::Protocol("catalog negative count".into()));
            }
            total_rows += rows as u64;
            total_bytes += bytes as u64;
            if total_rows > super::super::acquire::ROWS
                || total_bytes > super::super::acquire::RAW_BYTES
            {
                return Err(sqlx::Error::Protocol("catalog bounds".into()));
            }
            let statement = format!(
                "SELECT raw FROM ({}) c ORDER BY raw COLLATE \"C\"",
                query.sql
            );
            let values = sqlx::query(sqlx::AssertSqlSafe(statement))
                .fetch_all(&mut *sql)
                .await?;
            let values: Vec<Vec<u8>> = values
                .into_iter()
                .map(|v| v.get::<String, _>("raw").into_bytes())
                .collect();
            if values.len() != rows as usize
                || values.iter().map(Vec::len).sum::<usize>() != bytes as usize
            {
                return Err(sqlx::Error::Protocol("catalog count changed".into()));
            }
            raw.insert(query.name.to_owned(), values);
        }
        budget
            .sample(super::super::clock::now())
            .map_err(|_| sqlx::Error::Protocol("catalog terminal clock refused".into()))?;
        Ok(raw)
    }
    fn native_expected(raw: &std::collections::BTreeMap<String, Vec<Vec<u8>>>) -> Database {
        let mut db = database();
        let value: serde_json::Value = serde_json::from_slice(&raw["database"][0]).unwrap();
        db.database = value["name"].as_str().unwrap().to_owned();
        db.database_oid = value["oid"].as_u64().unwrap() as u32;
        assert!(db.database.starts_with("buzz_inspection_test_"));
        for bytes in &raw["roles"] {
            let row: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            match row["name"].as_str().unwrap() {
                INSPECTOR => db.inspector_oid = row["oid"].as_u64().unwrap() as u32,
                VIEW_OWNER => db.view_owner_oid = row["oid"].as_u64().unwrap() as u32,
                _ => (),
            }
        }
        for bytes in &raw["relations"] {
            let row: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            if row["schema"] == "buzz_inspection" {
                db.view_definition_sha256.insert(
                    row["name"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("v_")
                        .unwrap()
                        .to_owned(),
                    row["definition"].as_str().unwrap().to_owned(),
                );
            }
        }
        db
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "AUTHORED UNRUN: isolated admin/inspector roles, original migrations and prepared forward migration required"]
    async fn native_actual_catalog_refuses_direct_public_create_and_enforcement_drift_then_rolls_back(
    ) {
        use sqlx::{Connection, Executor};
        assert_eq!(
            std::env::var("BUZZ_INSPECTION_NATIVE").as_deref(),
            Ok("authorized-isolated")
        );
        let url =
            std::env::var("BUZZ_INSPECTION_NATIVE_ADMIN_URL").expect("isolated admin URL absent");
        let mut sql = sqlx::PgConnection::connect(&url)
            .await
            .expect("native connection failed");
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&mut sql)
            .await
            .unwrap();
        assert!(name.starts_with("buzz_inspection_test_"));
        let database_identifier = format!("\"{}\"", name.replace('"', "\"\""));
        sql.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .unwrap();
        let baseline=async {sqlx::raw_sql("SET LOCAL statement_timeout='20000'; SET LOCAL lock_timeout='1000'; SET LOCAL ROLE buzz_recovery_inspector").execute(&mut sql).await?;native_catalog(&mut sql).await}.await;
        let rolled_back = sql.execute("ROLLBACK").await;
        rolled_back.unwrap();
        let baseline = baseline.unwrap();
        let db = native_expected(&baseline);
        let digest = synthetic_catalog_digest(&baseline);
        assert!(verify_source(&baseline, &db, &digest).is_ok());
        // Every contrary DDL/ACL state is transaction-owned. Rollback happens
        // before any assertion about the expected verifier refusal.
        let cases=vec![
            format!("GRANT CREATE ON DATABASE {database_identifier} TO buzz_recovery_inspector"),
            format!("GRANT CREATE ON DATABASE {database_identifier} TO PUBLIC"),
            "ALTER TABLE public.enrollment_history DISABLE TRIGGER immutable_enrollment_history".into(),
            "ALTER TABLE public.observation_snapshot_entries DISABLE TRIGGER immutable_observation_snapshot_entries".into(),
            "DROP TRIGGER immutable_enrollment_history ON public.enrollment_history".into(),
            "DROP TRIGGER immutable_enrollment_history ON public.enrollment_history; CREATE TRIGGER immutable_enrollment_history BEFORE UPDATE OR DELETE ON public.enrollment_history FOR EACH ROW EXECUTE FUNCTION public.freeze_root_identity()".into(),
            "CREATE OR REPLACE FUNCTION public.deny_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END;$$".into(),
            "ALTER TABLE public.model_dispatches DISABLE TRIGGER immutable_model_dispatch".into(),
            "ALTER TABLE public.model_dispatches DISABLE TRIGGER no_delete_model_dispatch".into(),
            "ALTER TABLE public.native_attachments DISABLE TRIGGER immutable_native_attachments".into(),
            "ALTER TABLE public.native_attachment_leases DISABLE TRIGGER immutable_native_attachment_leases".into(),
            "CREATE OR REPLACE FUNCTION public.freeze_model_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END;$$".into(),
            "DROP INDEX public.unresolved_model_dispatch".into(),
            "DROP INDEX public.native_attachment_lease_lookup".into(),
            "ALTER TABLE public.model_dispatches DROP CONSTRAINT model_dispatches_generation_check".into(),
            "ALTER TABLE public.native_attachments DROP CONSTRAINT native_attachments_byte_length_check".into(),
            "ALTER TABLE public.native_attachment_leases DROP CONSTRAINT native_attachment_leases_binding_epoch_check".into(),
            "DROP INDEX public.one_active_principal_module".into(),
            "ALTER TABLE public.enrollment_challenges DROP CONSTRAINT enrollment_challenges_consumer_id_enrollment_id_key".into(),
            "ALTER TABLE public.observation_snapshot_entries DROP CONSTRAINT observation_snapshot_entries_snapshot_id_fkey".into(),
            "ALTER TABLE public.observation_snapshot_entries DROP CONSTRAINT observation_snapshot_entries_ordinal_check; ALTER TABLE public.observation_snapshot_entries ADD CONSTRAINT observation_snapshot_entries_ordinal_check CHECK (ordinal >= 0)".into(),
        ];
        for statement in cases {
            sql.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
                .await
                .unwrap();
            let outcome = async {
                sqlx::raw_sql("SET LOCAL statement_timeout='20000'; SET LOCAL lock_timeout='1000'")
                    .execute(&mut sql)
                    .await?;
                // The cases are fixed DDL plus current_database() quoted as an
                // SQL identifier above, never an unescaped fixture/request value.
                sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                    .execute(&mut sql)
                    .await?;
                sql.execute("SET LOCAL ROLE buzz_recovery_inspector")
                    .await?;
                let raw = native_catalog(&mut sql).await?;
                Ok::<bool, sqlx::Error>(verify_source(&raw, &db, &digest).is_err())
            }
            .await;
            let rollback = sql.execute("ROLLBACK").await;
            rollback.unwrap();
            assert!(outcome.expect("native owned DDL/catalog capture failed"));
        }
        sql.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .unwrap();
        let final_capture=async {sqlx::raw_sql("SET LOCAL statement_timeout='20000'; SET LOCAL lock_timeout='1000'; SET LOCAL ROLE buzz_recovery_inspector").execute(&mut sql).await?;native_catalog(&mut sql).await}.await;
        let rollback = sql.execute("ROLLBACK").await;
        let close = sql.close().await;
        rollback.unwrap();
        close.unwrap();
        let final_capture = final_capture.unwrap();
        assert_eq!(synthetic_catalog_digest(&final_capture), digest);
        assert!(verify_source(&final_capture, &db, &digest).is_ok());
    }
}
