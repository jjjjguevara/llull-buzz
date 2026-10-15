//! Fixed SQL acquisition plans. Aggregate budgets apply before ANY payload.
//! Raw inventory UTF-8 is distinct from the private signed-envelope byte ceiling.
use super::{deny, relations, Result};
use serde::{Deserialize, Serialize};
pub(crate) const ROWS: u64 = 10_000;
pub(crate) const RAW_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const CHUNK_BYTES: usize = 700_000;
pub(crate) const ENVELOPE_BYTES: usize = llull_buzz_wire::MAX_BYTES;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preflight {
    pub count: u64,
    pub bytes: u64,
    pub largest: u64,
    pub snapshot: String,
}
fn source(name: &str) -> Result<String> {
    let r = relations::relation(name)?;
    // name is a closed source registry symbol, never user-supplied SQL syntax.
    Ok(format!("SELECT row_key::text COLLATE \"C\" AS ordering, convert_to(jsonb_build_object('relation','{}','row_sha256',row_sha256,'row_key',row_key,'metadata',metadata)::text,'UTF8') AS raw FROM buzz_inspection.v_{}",r.name,r.name))
}
pub(crate) fn preflight_sql(name: &str) -> Result<String> {
    Ok(format!("WITH source AS MATERIALIZED ({}), snapshot AS MATERIALIZED (SELECT pg_current_snapshot()::text AS identity), bounds AS MATERIALIZED (SELECT count(*) AS n,coalesce(sum(octet_length(raw)),0) AS b,coalesce(max(octet_length(raw)),0) AS m FROM source) SELECT CASE WHEN octet_length(snapshot.identity)<=4096 THEN json_build_object('count',bounds.n,'bytes',bounds.b,'largest',bounds.m,'snapshot',snapshot.identity)::text ELSE '{{\"refused\":\"snapshot_scalar_bound\"}}' END FROM bounds CROSS JOIN snapshot",source(name)?))
}
/// Requires every fixed relation's scalar result, including lawful zero rows.
pub(crate) fn complete_preflight<'a>(
    facts: impl IntoIterator<Item = (&'a str, &'a Preflight)>,
) -> Result<String> {
    let mut names = std::collections::BTreeSet::new();
    let mut count = 0u64;
    let mut bytes = 0u64;
    let mut snapshot = None;
    for (name, fact) in facts {
        relations::relation(name)?;
        if fact.count > ROWS || fact.bytes > RAW_BYTES {
            return Err(unknown("inventory_aggregate_budget"));
        }
        if !names.insert(name)
            || fact.snapshot.is_empty()
            || fact.snapshot.len() > 4096
            || fact.largest > fact.bytes
            || (fact.count == 0) != (fact.bytes == 0)
            || (fact.count == 0) != (fact.largest == 0)
        {
            return Err(deny("inventory_preflight"));
        }
        if let Some(prior) = snapshot {
            if prior != fact.snapshot {
                return Err(deny("inventory_snapshot"));
            }
        } else {
            snapshot = Some(fact.snapshot.as_str());
        }
        count = count
            .checked_add(fact.count)
            .ok_or_else(|| deny("inventory_count_overflow"))?;
        bytes = bytes
            .checked_add(fact.bytes)
            .ok_or_else(|| deny("inventory_byte_overflow"))?;
    }
    if count > ROWS || bytes > RAW_BYTES {
        return Err(unknown("inventory_aggregate_budget"));
    }
    if names.len() != relations::RELATIONS.len() {
        return Err(deny("inventory_complete_preflight"));
    }
    Ok(snapshot.ok_or_else(|| deny("inventory_snapshot"))?.into())
}
pub(crate) fn declare_sql(name: &str, expected: &Preflight) -> Result<String> {
    relations::relation(name)?;
    if expected.count > ROWS || expected.bytes > RAW_BYTES || expected.largest > expected.bytes {
        return Err(deny("inventory_preflight"));
    }
    // Only checked integers enter the SQL statement. Snapshot equality is also
    // checked at every driver boundary; the caller never supplies a predicate.
    Ok(format!("DECLARE buzz_inspection_payload NO SCROLL CURSOR WITHOUT HOLD FOR WITH source AS MATERIALIZED ({}), bounds AS MATERIALIZED (SELECT count(*) AS n,coalesce(sum(octet_length(raw)),0) AS b,coalesce(max(octet_length(raw)),0) AS m FROM source), ordered AS MATERIALIZED (SELECT row_number() OVER (ORDER BY ordering) AS ordinal,raw FROM source) SELECT ordinal,offset_index AS chunk_index,(octet_length(raw)+{}-1)/{} AS chunks,octet_length(raw) AS row_bytes,encode(sha256(raw),'hex') AS payload_sha256,substring(raw FROM offset_index*{}+1 FOR {}) AS payload FROM ordered CROSS JOIN bounds CROSS JOIN LATERAL generate_series(0,(octet_length(raw)-1)/{}) AS offsets(offset_index) WHERE bounds.n={} AND bounds.b={} AND bounds.m={} AND bounds.n<={} AND bounds.b<={} ORDER BY ordinal,offset_index",source(name)?,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,expected.count,expected.bytes,expected.largest,ROWS,RAW_BYTES))
}
/// One FETCH returns at most one opaque chunk; a lawful 2MiB row need not fit
/// the unchanged 1MiB public wire parser or a smaller invented row ceiling.
pub(crate) const FETCH_SQL: &str = "FETCH FORWARD 1 FROM buzz_inspection_payload";
pub(crate) const CLOSE_SQL: &str = "CLOSE buzz_inspection_payload";
pub(crate) struct NativeSession {
    connection: Option<sqlx::PgConnection>,
    cursor_open: bool,
    transaction_open: bool,
    #[cfg(test)]
    inert: Option<InertSql>,
}
fn environment_closed() -> Result<()> {
    if std::env::vars_os().any(|(name, _)| name.to_string_lossy().starts_with("PG")) {
        return Err(deny("inspection_ambient_pg_options"));
    }
    Ok(())
}
fn unknown(code: &'static str) -> super::InspectionError {
    super::InspectionError::Unknown {
        code,
        first: None,
        cleanup: Vec::new(),
    }
}
impl NativeSession {
    pub(crate) async fn connect(
        auth: &super::authority::Authenticated,
        password: &[u8],
        certificate: &[u8],
        budget: &mut super::clock::Budget,
    ) -> Result<Self> {
        use sqlx::{ConnectOptions, Connection};
        environment_closed()?;
        let db = &auth.profile().database;
        if db.host.is_empty()
            || db.host.len() > 255
            || db.host.starts_with('/')
            || db.host.chars().any(|c| c.is_control() || c.is_whitespace())
            || llull_buzz_wire::sha256(certificate) != db.ssl_root_sha256
        {
            return Err(deny("inspection_connection_binding"));
        }
        let password =
            std::str::from_utf8(password).map_err(|_| deny("inspection_password_encoding"))?;
        if password.contains('\0') {
            return Err(deny("inspection_password_encoding"));
        }
        let options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
            .host(&db.host)
            .port(db.port)
            .database(&db.database)
            .username(super::authority::INSPECTOR)
            .password(password)
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(certificate.to_vec())
            .application_name("llull-buzz-private-inspection")
            .statement_cache_capacity(0)
            .options([
                ("default_transaction_read_only", "on"),
                ("search_path", super::catalog::INSPECTION_SEARCH_PATH),
                ("client_encoding", "UTF8"),
                ("timezone", "UTC"),
                ("statement_timeout", "20000"),
                ("lock_timeout", "1000"),
            ])
            .disable_statement_logging();
        budget.sample(super::clock::now())?;
        let remaining = budget.remaining()?;
        #[cfg(test)]
        let inert = INERT_SQL.with(|slot| slot.borrow_mut().take());
        #[cfg(test)]
        let inert_connection = inert.is_some();
        #[cfg(not(test))]
        let inert_connection = false;
        let connected = if inert_connection {
            None
        } else {
            Some(tokio::select! {
                biased;
                _ = budget.cancellation() => return Err(unknown("inspection_cancelled")),
                result = tokio::time::timeout(remaining, sqlx::PgConnection::connect_with(&options)) =>
                    result.map_err(|_| unknown("inspection_connect_timeout"))?.map_err(|_| unknown("inspection_connect"))?,
            })
        };
        let mut owned = Self {
            connection: connected,
            cursor_open: false,
            transaction_open: false,
            #[cfg(test)]
            inert,
        };
        let admitted = async {
            budget.sample(super::clock::now())?;
            owned
                .execute(
                    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
                    budget,
                )
                .await?;
            // Zero-row fixed view reads acquire view/base relation read locks
            // before catalog/definition qualification and before payload. No
            // original or projected record crosses this initialization boundary.
            for relation in relations::RELATIONS {
                owned
                    .execute(
                        &format!("SELECT 1 FROM buzz_inspection.v_{} LIMIT 0", relation.name),
                        budget,
                    )
                    .await?;
            }
            // Ambiguous admission still owns rollback and connection cleanup.
            budget.sample(super::clock::now())?;
            Ok(())
        }
        .await;
        if let Err(first) = admitted {
            return owned.finish(Err(first), budget).await;
        }
        Ok(owned)
    }
    fn connection(&mut self) -> Result<&mut sqlx::PgConnection> {
        self.connection
            .as_mut()
            .ok_or_else(|| deny("inspection_connection_closed"))
    }
    pub(crate) async fn execute(
        &mut self,
        sql: &str,
        budget: &mut super::clock::Budget,
    ) -> Result<()> {
        budget.sample(super::clock::now())?;
        let remaining = budget.remaining()?;
        if sql.starts_with("BEGIN ") {
            self.transaction_open = true;
        }
        if sql.starts_with("DECLARE ") {
            self.cursor_open = true;
        }
        #[cfg(test)]
        if let Some(inert) = &mut self.inert {
            inert.execute(sql)?;
            budget.sample(super::clock::now())?;
            if sql == CLOSE_SQL {
                self.cursor_open = false;
            }
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = budget.cancellation() => return Err(unknown("inspection_cancelled")),
            result = tokio::time::timeout(remaining, sqlx::query(sql).execute(self.connection()?)) => {
                result.map_err(|_| unknown("inspection_sql_timeout"))?.map_err(|_| unknown("inspection_sql"))?;
            }
        }
        budget.sample(super::clock::now())?;
        if sql == CLOSE_SQL {
            self.cursor_open = false;
        }
        Ok(())
    }
    pub(crate) async fn scalar(
        &mut self,
        sql: &str,
        budget: &mut super::clock::Budget,
    ) -> Result<String> {
        budget.sample(super::clock::now())?;
        let remaining = budget.remaining()?;
        #[cfg(test)]
        if let Some(inert) = &mut self.inert {
            let value = inert.scalar(sql)?;
            if value.len() > 8192 {
                return Err(unknown("inspection_scalar_bound"));
            }
            budget.sample(super::clock::now())?;
            return Ok(value);
        }
        let value: String = tokio::select! {
            biased;
            _ = budget.cancellation() => return Err(unknown("inspection_cancelled")),
            result = tokio::time::timeout(remaining, sqlx::query_scalar(sql).fetch_one(self.connection()?)) =>
                result.map_err(|_| unknown("inspection_sql_timeout"))?.map_err(|_| unknown("inspection_scalar"))?,
        };
        // Scalar queries themselves are fixed projections; no inventory body is
        // transferred here. Exact scalar-header limits remain independently bounded.
        if value.len() > 8192 {
            return Err(unknown("inspection_scalar_bound"));
        }
        budget.sample(super::clock::now())?;
        Ok(value)
    }
    async fn cleanup_command(&mut self, sql: &str) -> bool {
        #[cfg(test)]
        if let Some(inert) = &mut self.inert {
            return inert.execute(sql).is_ok();
        }
        let Ok(connection) = self.connection() else {
            return false;
        };
        matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                sqlx::query(sql).execute(connection)
            )
            .await,
            Ok(Ok(_))
        )
    }
    async fn close_transport(&mut self) -> bool {
        use sqlx::Connection;
        #[cfg(test)]
        if let Some(mut inert) = self.inert.take() {
            return inert.close();
        }
        if let Some(connection) = self.connection.take() {
            matches!(
                tokio::time::timeout(std::time::Duration::from_secs(1), connection.close()).await,
                Ok(Ok(()))
            )
        } else {
            false
        }
    }
    pub(crate) async fn finish<T>(
        &mut self,
        first: Result<T>,
        budget: &mut super::clock::Budget,
    ) -> Result<T> {
        let mut faults = Vec::new();
        // Cancellation/time refusal never skips cleanup. The three protocol
        // attempts retain their original independent one-second termination caps.
        if self.cursor_open {
            if !self.cleanup_command(CLOSE_SQL).await {
                faults.push("inspection_cursor_close");
            }
            self.cursor_open = false;
        }
        if self.transaction_open {
            if !self.cleanup_command("ROLLBACK").await {
                faults.push("inspection_rollback");
            }
            self.transaction_open = false;
        }
        if !self.close_transport().await {
            faults.push("inspection_connection_close");
        }
        tokio::task::yield_now().await;
        let terminal = budget.sample(super::clock::now());
        let first = match first {
            Ok(value) => terminal.map(|_| value),
            Err(error) => Err(error),
        };
        if !faults.is_empty() {
            return Err(super::InspectionError::Unknown {
                code: "inspection_sql_cleanup",
                first: first.err().map(Box::new),
                cleanup: faults,
            });
        }
        first
    }
}

struct Chunk {
    ordinal: u64,
    index: u64,
    chunks: u64,
    row_bytes: u64,
    digest: String,
    bytes: Vec<u8>,
}
/// The actual native FETCH path and inert source controls share this verifier.
/// EOF is an explicit terminal fact; no partial ledger can produce retained rows.
struct ChunkLedger<'a> {
    expected: &'a Preflight,
    rows: Vec<Vec<u8>>,
    current: Option<Chunk>,
    next_index: u64,
    total: u64,
    largest: u64,
    failed: bool,
}
impl<'a> ChunkLedger<'a> {
    fn new(expected: &'a Preflight) -> Result<Self> {
        if expected.count > ROWS
            || expected.bytes > RAW_BYTES
            || expected.largest > expected.bytes
            || (expected.count == 0) != (expected.bytes == 0)
            || (expected.count == 0) != (expected.largest == 0)
        {
            return Err(unknown("inventory_preflight"));
        }
        Ok(Self {
            expected,
            rows: Vec::new(),
            current: None,
            next_index: 0,
            total: 0,
            largest: 0,
            failed: false,
        })
    }
    fn accept(&mut self, chunk: Chunk) -> Result<()> {
        if self.failed {
            return Err(unknown("inventory_sticky_refusal"));
        }
        let result = self.accept_checked(chunk);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_checked(&mut self, chunk: Chunk) -> Result<()> {
        let ordinal = self.rows.len() as u64 + 1;
        if chunk.ordinal != ordinal
            || chunk.index != self.next_index
            || chunk.row_bytes == 0
            || chunk.row_bytes > self.expected.largest
            || chunk.row_bytes > RAW_BYTES
            || chunk.chunks != chunk.row_bytes.div_ceil(CHUNK_BYTES as u64)
            || ordinal > self.expected.count
        {
            return Err(unknown("inventory_chunk_identity"));
        }
        llull_buzz_wire::hash(&chunk.digest).map_err(|_| deny("inventory_chunk_digest"))?;
        if let Some(current) = self.current.as_mut() {
            if chunk.chunks != current.chunks
                || chunk.row_bytes != current.row_bytes
                || chunk.digest != current.digest
                || chunk.bytes.len() as u64
                    != (current.row_bytes - current.bytes.len() as u64).min(CHUNK_BYTES as u64)
            {
                return Err(unknown("inventory_chunk_identity"));
            }
            current.bytes.extend_from_slice(&chunk.bytes);
        } else {
            if chunk.bytes.len() as u64 != chunk.row_bytes.min(CHUNK_BYTES as u64) {
                return Err(unknown("inventory_chunk_identity"));
            }
            self.current = Some(chunk);
        }
        self.next_index += 1;
        let complete = self
            .current
            .as_ref()
            .is_some_and(|c| self.next_index == c.chunks);
        if complete {
            let current = self
                .current
                .take()
                .ok_or_else(|| unknown("inventory_chunk_identity"))?;
            if current.bytes.len() as u64 != current.row_bytes
                || llull_buzz_wire::sha256(&current.bytes) != current.digest
            {
                return Err(unknown("inventory_payload_digest"));
            }
            self.total = self
                .total
                .checked_add(current.row_bytes)
                .ok_or_else(|| unknown("inventory_counter_overflow"))?;
            if self.total > self.expected.bytes || self.total > RAW_BYTES {
                return Err(unknown("inventory_payload_overflow"));
            }
            self.largest = self.largest.max(current.row_bytes);
            self.rows.push(current.bytes);
            self.next_index = 0;
        }
        Ok(())
    }
    fn eof(self) -> Result<Vec<Vec<u8>>> {
        if self.failed
            || self.current.is_some()
            || self.rows.len() as u64 != self.expected.count
            || self.total != self.expected.bytes
            || self.largest != self.expected.largest
        {
            return Err(unknown("inventory_totals_eof"));
        }
        Ok(self.rows)
    }
}
fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| deny("inventory_chunk_counters"))
}
impl NativeSession {
    async fn next_chunk(&mut self, budget: &mut super::clock::Budget) -> Result<Option<Chunk>> {
        use sqlx::Row;
        budget.sample(super::clock::now())?;
        let remaining = budget.remaining()?;
        #[cfg(test)]
        if let Some(inert) = &mut self.inert {
            let result = inert.next();
            budget.sample(super::clock::now())?;
            return result;
        }
        let row = tokio::select! {
            biased;
            _ = budget.cancellation() => return Err(unknown("inspection_cancelled")),
            result = tokio::time::timeout(remaining, sqlx::query(FETCH_SQL).fetch_optional(self.connection()?)) =>
                result.map_err(|_| unknown("inventory_fetch_timeout"))?.map_err(|_| unknown("inventory_fetch"))?,
        };
        let chunk = row
            .map(|row| -> Result<Chunk> {
                Ok(Chunk {
                    ordinal: nonnegative(
                        row.try_get::<i64, _>("ordinal")
                            .map_err(|_| deny("inventory_chunk_shape"))?,
                    )?,
                    index: nonnegative(
                        row.try_get::<i32, _>("chunk_index")
                            .map_err(|_| deny("inventory_chunk_shape"))?
                            as i64,
                    )?,
                    chunks: nonnegative(
                        row.try_get::<i32, _>("chunks")
                            .map_err(|_| deny("inventory_chunk_shape"))?
                            as i64,
                    )?,
                    row_bytes: nonnegative(
                        row.try_get::<i32, _>("row_bytes")
                            .map_err(|_| deny("inventory_chunk_shape"))?
                            as i64,
                    )?,
                    digest: row
                        .try_get("payload_sha256")
                        .map_err(|_| deny("inventory_chunk_shape"))?,
                    bytes: row
                        .try_get("payload")
                        .map_err(|_| deny("inventory_chunk_shape"))?,
                })
            })
            .transpose()?;
        budget.sample(super::clock::now())?;
        Ok(chunk)
    }
    pub(crate) async fn check_snapshot(
        &mut self,
        expected: &str,
        budget: &mut super::clock::Budget,
    ) -> Result<()> {
        let actual=self.scalar("SELECT CASE WHEN octet_length(pg_current_snapshot()::text)<=4096 THEN pg_current_snapshot()::text ELSE 'snapshot-scalar-bound-refusal' END",budget).await?;
        if actual != expected {
            return Err(unknown("inventory_snapshot_changed"));
        }
        Ok(())
    }
    pub(crate) async fn collect_relation(
        &mut self,
        name: &str,
        preflight: &Preflight,
        budget: &mut super::clock::Budget,
    ) -> Result<Vec<Vec<u8>>> {
        self.check_snapshot(&preflight.snapshot, budget).await?;
        self.execute(&declare_sql(name, preflight)?, budget).await?;
        self.collect_declared(preflight, budget).await
    }
    async fn collect_declared(
        &mut self,
        preflight: &Preflight,
        budget: &mut super::clock::Budget,
    ) -> Result<Vec<Vec<u8>>> {
        let mut ledger = ChunkLedger::new(preflight)?;
        while let Some(chunk) = self.next_chunk(budget).await? {
            ledger.accept(chunk)?;
            budget.sample(super::clock::now())?;
        }
        let rows = ledger.eof()?;
        self.execute(CLOSE_SQL, budget).await?;
        self.check_snapshot(&preflight.snapshot, budget).await?;
        Ok(rows)
    }
}

impl NativeSession {
    pub(crate) async fn inventory_preflights(
        &mut self,
        budget: &mut super::clock::Budget,
    ) -> Result<std::collections::BTreeMap<String, Preflight>> {
        let mut facts = std::collections::BTreeMap::new();
        for relation in relations::RELATIONS {
            let raw = self.scalar(&preflight_sql(relation.name)?, budget).await?;
            let fact: Preflight = super::json::decode(raw.as_bytes())?;
            facts.insert(relation.name.into(), fact);
            budget.sample(super::clock::now())?;
        }
        let snapshot = complete_preflight(facts.iter().map(|(name, fact)| (name.as_str(), fact)))?;
        self.check_snapshot(&snapshot, budget).await?;
        Ok(facts)
    }
    pub(crate) async fn collect_inventory(
        &mut self,
        facts: &std::collections::BTreeMap<String, Preflight>,
        budget: &mut super::clock::Budget,
    ) -> Result<std::collections::BTreeMap<String, Vec<Vec<u8>>>> {
        // Cannot initiate payload for a supplied subset or independently fresh
        // relation: the closed complete aggregate preflight is mandatory here too.
        complete_preflight(facts.iter().map(|(name, fact)| (name.as_str(), fact)))?;
        let mut retained = std::collections::BTreeMap::new();
        for relation in relations::RELATIONS {
            let fact = facts
                .get(relation.name)
                .ok_or_else(|| deny("inventory_preflight_missing"))?;
            let rows = self.collect_relation(relation.name, fact, budget).await?;
            retained.insert(relation.name.into(), rows);
            budget.sample(super::clock::now())?;
        }
        Ok(retained)
    }
}

fn catalog_source(name: &str) -> Result<&'static str> {
    super::catalog::QUERIES
        .iter()
        .find(|q| q.name == name)
        .map(|q| q.sql)
        .ok_or_else(|| deny("catalog_selector"))
}
fn catalog_preflight_sql(name: &str) -> Result<String> {
    Ok(format!("WITH source AS MATERIALIZED ({}), bounds AS MATERIALIZED (SELECT count(*) AS n,coalesce(sum(octet_length(convert_to(raw,'UTF8'))),0) AS b,coalesce(max(octet_length(convert_to(raw,'UTF8'))),0) AS m FROM source), snapshot AS MATERIALIZED (SELECT pg_current_snapshot()::text AS identity) SELECT CASE WHEN octet_length(identity)<=4096 THEN json_build_object('count',n,'bytes',b,'largest',m,'snapshot',identity)::text ELSE '{{\"refused\":\"snapshot_scalar_bound\"}}' END FROM bounds CROSS JOIN snapshot",catalog_source(name)?))
}
fn catalog_declare_sql(name: &str, fact: &Preflight) -> Result<String> {
    if fact.count > ROWS || fact.bytes > RAW_BYTES || fact.largest > fact.bytes {
        return Err(unknown("catalog_budget"));
    }
    Ok(format!("DECLARE buzz_inspection_payload NO SCROLL CURSOR WITHOUT HOLD FOR WITH source AS MATERIALIZED ({}), bounds AS MATERIALIZED (SELECT count(*) AS n,coalesce(sum(octet_length(convert_to(raw,'UTF8'))),0) AS b,coalesce(max(octet_length(convert_to(raw,'UTF8'))),0) AS m FROM source), ordered AS MATERIALIZED (SELECT row_number() OVER (ORDER BY raw COLLATE \"C\") AS ordinal,convert_to(raw,'UTF8') AS raw FROM source) SELECT ordinal,offset_index AS chunk_index,(octet_length(raw)+{}-1)/{} AS chunks,octet_length(raw) AS row_bytes,encode(sha256(raw),'hex') AS payload_sha256,substring(raw FROM offset_index*{}+1 FOR {}) AS payload FROM ordered CROSS JOIN bounds CROSS JOIN LATERAL generate_series(0,(octet_length(raw)-1)/{}) AS offsets(offset_index) WHERE bounds.n={} AND bounds.b={} AND bounds.m={} AND bounds.n<={} AND bounds.b<={} ORDER BY ordinal,offset_index",catalog_source(name)?,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,CHUNK_BYTES,fact.count,fact.bytes,fact.largest,ROWS,RAW_BYTES))
}
impl NativeSession {
    pub(crate) async fn catalog_preflights(
        &mut self,
        budget: &mut super::clock::Budget,
    ) -> Result<std::collections::BTreeMap<String, Preflight>> {
        let mut facts = std::collections::BTreeMap::new();
        let mut total_rows = 0u64;
        let mut total_bytes = 0u64;
        let mut snapshot = None;
        for query in super::catalog::QUERIES {
            let raw = self
                .scalar(&catalog_preflight_sql(query.name)?, budget)
                .await?;
            let fact: Preflight = super::json::decode(raw.as_bytes())?;
            if fact.count > ROWS
                || fact.bytes > RAW_BYTES
                || fact.largest > fact.bytes
                || (fact.count == 0) != (fact.bytes == 0)
                || (fact.count == 0) != (fact.largest == 0)
            {
                return Err(unknown("catalog_preflight"));
            }
            total_rows = total_rows
                .checked_add(fact.count)
                .ok_or_else(|| unknown("catalog_count_overflow"))?;
            total_bytes = total_bytes
                .checked_add(fact.bytes)
                .ok_or_else(|| unknown("catalog_byte_overflow"))?;
            if total_rows > ROWS || total_bytes > RAW_BYTES {
                return Err(unknown("catalog_budget"));
            }
            if let Some(ref prior) = snapshot {
                if *prior != fact.snapshot {
                    return Err(unknown("catalog_snapshot"));
                }
            } else {
                snapshot = Some(fact.snapshot.clone());
            }
            facts.insert(query.name.into(), fact);
            budget.sample(super::clock::now())?;
        }
        self.check_snapshot(
            snapshot
                .as_deref()
                .ok_or_else(|| unknown("catalog_scope"))?,
            budget,
        )
        .await?;
        Ok(facts)
    }
    pub(crate) async fn collect_catalog(
        &mut self,
        facts: &std::collections::BTreeMap<String, Preflight>,
        budget: &mut super::clock::Budget,
    ) -> Result<std::collections::BTreeMap<String, Vec<Vec<u8>>>> {
        if facts.len() != super::catalog::QUERIES.len()
            || super::catalog::QUERIES
                .iter()
                .any(|q| !facts.contains_key(q.name))
        {
            return Err(deny("catalog_scope"));
        }
        let mut retained = std::collections::BTreeMap::new();
        for query in super::catalog::QUERIES {
            let fact = &facts[query.name];
            self.check_snapshot(&fact.snapshot, budget).await?;
            self.execute(&catalog_declare_sql(query.name, fact)?, budget)
                .await?;
            // The same opaque-chunk verifier is used; only the closed SELECT
            // source differs. No ordinary fetch_all materializes large catalogs.
            let rows = self.collect_declared(fact, budget).await?;
            retained.insert(query.name.into(), rows);
        }
        Ok(retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn full(count: u64, bytes: u64) -> std::collections::BTreeMap<String, Preflight> {
        relations::RELATIONS
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    r.name.into(),
                    Preflight {
                        count: if i == 0 { count } else { 0 },
                        bytes: if i == 0 { bytes } else { 0 },
                        largest: if i == 0 { bytes / count.max(1) } else { 0 },
                        snapshot: "1:2:".into(),
                    },
                )
            })
            .collect()
    }
    #[test]
    fn actual_aggregate_preflight_admits_201_1000_and_full_2mib_row() {
        for (count, bytes) in [(0, 0), (201, 20100), (1000, 100000), (1, RAW_BYTES)] {
            let facts = full(count, bytes);
            assert_eq!(
                complete_preflight(facts.iter().map(|(n, f)| (n.as_str(), f))).unwrap(),
                "1:2:"
            );
        }
    }
    #[test]
    fn actual_aggregate_preflight_refuses_subset_mixed_snapshot_and_overquota() {
        let mut facts = full(1, RAW_BYTES);
        facts.get_mut("consumer_registry").unwrap().count = 1;
        facts.get_mut("consumer_registry").unwrap().bytes = 1;
        facts.get_mut("consumer_registry").unwrap().largest = 1;
        assert!(matches!(
            complete_preflight(facts.iter().map(|(n, f)| (n.as_str(), f))),
            Err(super::super::InspectionError::Unknown { .. })
        ));
        let mut facts = full(201, 20100);
        facts.remove("consumer_registry");
        assert!(complete_preflight(facts.iter().map(|(n, f)| (n.as_str(), f))).is_err());
        let mut facts = full(201, 20100);
        facts.get_mut("consumer_registry").unwrap().snapshot = "2:3:".into();
        assert!(complete_preflight(facts.iter().map(|(n, f)| (n.as_str(), f))).is_err());
    }
    #[test]
    fn fixed_actual_sql_cannot_admit_injected_identifier_or_fetch_before_guard() {
        assert!(source("resource_replays;DROP TABLE attempts").is_err());
        let fact = Preflight {
            count: 201,
            bytes: 20100,
            largest: 100,
            snapshot: "1:2:".into(),
        };
        let sql = declare_sql("resource_replays", &fact).unwrap();
        assert!(sql.starts_with("DECLARE buzz_inspection_payload NO SCROLL CURSOR WITHOUT HOLD"));
        assert!(sql.contains("source AS MATERIALIZED"));
        assert!(sql.contains("bounds.n=201"));
        assert!(sql.contains("bounds.b=20100"));
        assert_eq!(FETCH_SQL, "FETCH FORWARD 1 FROM buzz_inspection_payload");
    }
    fn chunks(raw: &[u8], ordinal: u64) -> Vec<Chunk> {
        let digest = llull_buzz_wire::sha256(raw);
        let total = raw.len().div_ceil(CHUNK_BYTES) as u64;
        raw.chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, bytes)| Chunk {
                ordinal,
                index: index as u64,
                chunks: total,
                row_bytes: raw.len() as u64,
                digest: digest.clone(),
                bytes: bytes.to_vec(),
            })
            .collect()
    }
    #[test]
    fn genuine_native_chunk_ledger_preserves_201_1000_and_full_2mib_row() {
        for count in [201u64, 1000u64] {
            let raw = r#"{"value":9007199254740993,"name":"é","null":null}"#.as_bytes();
            let fact = Preflight {
                count,
                bytes: count * raw.len() as u64,
                largest: raw.len() as u64,
                snapshot: "1:2:".into(),
            };
            let mut ledger = ChunkLedger::new(&fact).unwrap();
            for ordinal in 1..=count {
                for chunk in chunks(raw, ordinal) {
                    ledger.accept(chunk).unwrap();
                }
            }
            let retained = ledger.eof().unwrap();
            assert_eq!(retained.len() as u64, count);
            assert!(retained.iter().all(|r| r == raw));
        }
        let raw = vec![b'x'; RAW_BYTES as usize];
        let fact = Preflight {
            count: 1,
            bytes: RAW_BYTES,
            largest: RAW_BYTES,
            snapshot: "1:2:".into(),
        };
        let mut ledger = ChunkLedger::new(&fact).unwrap();
        for chunk in chunks(&raw, 1) {
            ledger.accept(chunk).unwrap();
        }
        assert_eq!(ledger.eof().unwrap()[0], raw);
    }
    #[test]
    fn genuine_native_chunk_ledger_refuses_early_eof_corruption_and_extra_rows_stickily() {
        let raw = vec![b'x'; CHUNK_BYTES + 1];
        let fact = Preflight {
            count: 1,
            bytes: raw.len() as u64,
            largest: raw.len() as u64,
            snapshot: "1:2:".into(),
        };
        let mut ledger = ChunkLedger::new(&fact).unwrap();
        ledger.accept(chunks(&raw, 1).remove(0)).unwrap();
        assert!(ledger.eof().is_err());
        let mut ledger = ChunkLedger::new(&fact).unwrap();
        let mut corrupt = chunks(&raw, 1);
        corrupt[0].bytes[0] = b'y';
        for chunk in corrupt {
            if ledger.accept(chunk).is_err() {
                break;
            }
        }
        assert!(ledger.eof().is_err());
        let raw = b"x";
        let fact = Preflight {
            count: 1,
            bytes: 1,
            largest: 1,
            snapshot: "1:2:".into(),
        };
        let mut ledger = ChunkLedger::new(&fact).unwrap();
        ledger.accept(chunks(raw, 1).remove(0)).unwrap();
        assert!(ledger.accept(chunks(raw, 2).remove(0)).is_err());
        assert!(ledger.eof().is_err());
    }
}

// AUTHORED UNRUN: only the final SQL socket is inert. The production fixed SQL,
// preflight/page ledger, catalog/history/authentication and owner cleanup remain
// the actual functions. This thread-local seam does not exist in a release build.
#[cfg(test)]
thread_local! { static INERT_SQL: std::cell::RefCell<Option<InertSql>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(super) struct InertSql {
    pub session: String,
    pub inventory: std::collections::BTreeMap<String, Vec<Vec<u8>>>,
    pub catalogs: std::collections::BTreeMap<String, Vec<Vec<u8>>>,
    pub fault: &'static str,
    pub cleanup_fault: &'static str,
    pub log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    cursor: std::collections::VecDeque<Chunk>,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
#[cfg(test)]
impl InertSql {
    pub(super) fn new(
        session: String,
        inventory: std::collections::BTreeMap<String, Vec<Vec<u8>>>,
        catalogs: std::collections::BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Self {
        Self {
            session,
            inventory,
            catalogs,
            fault: "",
            cleanup_fault: "",
            log: Default::default(),
            cursor: Default::default(),
            cancellation: None,
        }
    }
    pub(super) fn install(self) {
        INERT_SQL.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(self);
        });
    }
    pub(super) fn clear() {
        INERT_SQL.with(|slot| {
            slot.borrow_mut().take();
        });
    }
    fn fact(rows: &[Vec<u8>]) -> Preflight {
        Preflight {
            count: rows.len() as u64,
            bytes: rows.iter().map(|r| r.len() as u64).sum(),
            largest: rows.iter().map(|r| r.len() as u64).max().unwrap_or(0),
            snapshot: "1:2:".into(),
        }
    }
    fn scalar(&mut self, sql: &str) -> Result<String> {
        self.log.borrow_mut().push(format!("scalar:{sql}"));
        if sql == super::catalog::SESSION_SQL {
            return Ok(self.session.clone());
        }
        if sql.starts_with("SELECT CASE WHEN octet_length(pg_current_snapshot()") {
            return Ok("1:2:".into());
        }
        for (name, rows) in &self.inventory {
            if sql == preflight_sql(name)? {
                let mut fact = Self::fact(rows);
                if self.fault == "oversize" {
                    fact.bytes = RAW_BYTES + 1;
                    fact.largest = fact.bytes;
                }
                return serde_json::to_string(&fact).map_err(|_| deny("inert_scalar"));
            }
        }
        for (name, rows) in &self.catalogs {
            if sql == catalog_preflight_sql(name)? {
                return serde_json::to_string(&Self::fact(rows)).map_err(|_| deny("inert_scalar"));
            }
        }
        Err(deny("inert_unexpected_sql"))
    }
    fn execute(&mut self, sql: &str) -> Result<()> {
        self.log.borrow_mut().push(format!("execute:{sql}"));
        if sql == "ROLLBACK" {
            if self.fault == "cancel-cleanup" {
                if let Some(flag) = &self.cancellation {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            return if self.fault == "rollback" || self.cleanup_fault == "rollback" {
                Err(unknown("inert_rollback"))
            } else {
                Ok(())
            };
        }
        if sql == CLOSE_SQL {
            self.cursor.clear();
            return if self.fault == "cursor-close" {
                Err(unknown("inert_cursor_close"))
            } else {
                Ok(())
            };
        }
        if sql == "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" {
            if self.fault == "cancel-connect" {
                if let Some(flag) = &self.cancellation {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            return Ok(());
        }
        if relations::RELATIONS
            .iter()
            .any(|r| sql == format!("SELECT 1 FROM buzz_inspection.v_{} LIMIT 0", r.name))
        {
            return Ok(());
        }
        let mut selected = None;
        for (name, rows) in &self.inventory {
            if sql == declare_sql(name, &Self::fact(rows))? {
                selected = Some(rows);
            }
        }
        for (name, rows) in &self.catalogs {
            if sql == catalog_declare_sql(name, &Self::fact(rows))? {
                selected = Some(rows);
            }
        }
        let rows = selected.ok_or_else(|| deny("inert_unexpected_sql"))?;
        self.cursor.clear();
        for (index, row) in rows.iter().enumerate() {
            for (offset, bytes) in row.chunks(CHUNK_BYTES).enumerate() {
                self.cursor.push_back(Chunk {
                    ordinal: index as u64 + 1,
                    index: offset as u64,
                    chunks: row.len().div_ceil(CHUNK_BYTES) as u64,
                    row_bytes: row.len() as u64,
                    digest: llull_buzz_wire::sha256(row),
                    bytes: bytes.to_vec(),
                });
            }
        }
        Ok(())
    }
    fn next(&mut self) -> Result<Option<Chunk>> {
        self.log.borrow_mut().push("fetch".into());
        if self.fault == "fetch" {
            return Err(unknown("inert_fetch"));
        }
        if self.fault == "early-eof" {
            self.cursor.clear();
        }
        let mut next = self.cursor.pop_front();
        if let Some(chunk) = &mut next {
            if self.fault == "chunk-digest" {
                chunk.digest = "0".repeat(64);
            }
            if self.fault == "chunk-order" {
                chunk.index += 1;
            }
        }
        Ok(next)
    }
    fn close(&mut self) -> bool {
        self.log.borrow_mut().push("close".into());
        self.fault != "connection-close" && self.cleanup_fault != "connection-close"
    }
}
