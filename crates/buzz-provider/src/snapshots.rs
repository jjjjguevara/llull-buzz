//! Recovery across observation gaps without silently skipping durable acceptance.
use crate::{
    auth::{self, Claims, Headers, SignedRequest, Target},
    db::Tx,
    CommandResult, Observation, Provider, Result,
};
use llull_buzz_wire::{id, sha256, Command, Execution, Fault, Resource};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{types::Json, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotQuery {
    pub cursor: Option<Uuid>,
    pub limit: Option<u16>,
}
impl SnapshotQuery {
    pub fn path(&self, id: Uuid) -> llull_buzz_wire::Result<String> {
        if self.limit.is_some_and(|n| n == 0 || n > 100) {
            return Err(Fault::Invalid);
        }
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(cursor) = self.cursor {
            query.append_pair("cursor", &cursor.to_string());
        }
        if let Some(limit) = self.limit {
            query.append_pair("limit", &limit.to_string());
        }
        let query = query.finish();
        Ok(format!(
            "/integration/v1/observation-snapshots/{id}{}{}",
            if query.is_empty() { "" } else { "?" },
            query
        ))
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPage {
    pub snapshot_id: Uuid,
    pub observations: Vec<Observation>,
    pub cursor: Uuid,
    pub complete: bool,
    pub committed_high_water: u64,
    pub recovery_epoch: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSnapshot {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckSnapshot {
    snapshot_id: Uuid,
    cursor: Uuid,
    durable_receipt_id: String,
}

impl Provider {
    pub async fn create_snapshot(
        &self,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        let _: CreateSnapshot = c.payload()?;
        if c.operation != "create-snapshot"
            || c.resource.reference != "observations"
            || c.resource.revision != "1"
        {
            return Err(Fault::Denied.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                "/integration/v1/observation-snapshots",
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        if let Some(response) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(response);
        }
        let high_water: i64 = sqlx::query_scalar(
            "SELECT next_sequence FROM observation_counters WHERE consumer_id=$1",
        )
        .bind(&c.consumer_id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(0);
        let snapshot = Uuid::new_v4();
        sqlx::query("INSERT INTO observation_snapshots(snapshot_id,consumer_id,module_id,context_domain,recovery_epoch,high_water) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(snapshot).bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64).bind(high_water).execute(&mut *tx).await?;
        // The ordered admission transaction freezes a complete boundary. Retained
        // history can reconstruct references even after the delivery watermark.
        let count = sqlx::query("INSERT INTO observation_snapshot_entries(snapshot_id,ordinal,record) SELECT $1,row_number() OVER(ORDER BY sequence),record FROM (SELECT DISTINCT ON(record->>'operation',record->>'operation_id') sequence,record FROM observations WHERE consumer_id=$2 AND module_id=$3 AND context_domain=$4 AND sequence<=$5 ORDER BY record->>'operation',record->>'operation_id',sequence DESC) latest")
            .bind(snapshot).bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(high_water).execute(&mut *tx).await?.rows_affected();
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result = Self::remember(&mut tx, (&c,&claims), snapshot.to_string(), Execution::Completed, 1,
            json!({"snapshot_id":snapshot,"count":count,"committed_high_water":high_water,"recovery_epoch":claims.recovery_epoch})).await?;
        tx.commit().await?;
        Ok(result)
    }

    async fn snapshot_boundary(
        tx: &mut Tx,
        id: Uuid,
        consumer: &str,
        claims: &Claims,
    ) -> Result<(i64, i64)> {
        let row = sqlx::query("SELECT high_water,recovery_epoch,expires_at>clock_timestamp() AS live,(SELECT count(*) FROM observation_snapshot_entries e WHERE e.snapshot_id=s.snapshot_id) AS count FROM observation_snapshots s WHERE snapshot_id=$1 AND consumer_id=$2 AND module_id=$3 AND context_domain=$4")
            .bind(id).bind(consumer).bind(&claims.module_id).bind(&claims.context_domain).fetch_optional(&mut **tx).await?.ok_or(Fault::Denied)?;
        if !row.try_get::<bool, _>("live")?
            || row.try_get::<i64, _>("recovery_epoch")? as u64 != claims.recovery_epoch
        {
            return Err(Fault::Gap.into());
        }
        Ok((row.try_get("high_water")?, row.try_get("count")?))
    }

    pub async fn snapshot_page(
        &self,
        consumer: &str,
        snapshot: Uuid,
        query: SnapshotQuery,
        headers: Headers<'_>,
    ) -> Result<SnapshotPage> {
        id(consumer)?;
        let path = query.path(snapshot)?;
        let reference = snapshot.to_string();
        let resource = Resource {
            namespace: consumer.into(),
            reference: reference.clone(),
            revision: "1".into(),
        };
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize(
                &mut tx,
                &SignedRequest {
                    headers: &headers,
                    body: b"",
                },
                auth::INVOCATION,
                &path,
                "GET",
                &Target {
                    consumer,
                    intent: &reference,
                    operation: "read-snapshot",
                    resource: &resource,
                    fingerprint: &sha256(b""),
                    root: None,
                },
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let (high_water, count) =
            Self::snapshot_boundary(&mut tx, snapshot, consumer, &claims).await?;
        let after: i64 = if let Some(cursor) = query.cursor {
            sqlx::query_scalar("SELECT through FROM observation_snapshot_cursors WHERE cursor_id=$1 AND snapshot_id=$2")
                .bind(cursor).bind(snapshot).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?
        } else {
            0
        };
        if after > count {
            return Err(Fault::Conflict.into());
        }
        let rows: Vec<Json<Observation>> = sqlx::query_scalar("SELECT record FROM observation_snapshot_entries WHERE snapshot_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT $3")
            .bind(snapshot).bind(after).bind(query.limit.unwrap_or(100) as i64).fetch_all(&mut *tx).await?;
        let through = after + rows.len() as i64;
        sqlx::query("INSERT INTO observation_snapshot_cursors(cursor_id,snapshot_id,through) VALUES($1,$2,$3) ON CONFLICT(snapshot_id,through) DO NOTHING")
            .bind(Uuid::new_v4()).bind(snapshot).bind(through).execute(&mut *tx).await?;
        let cursor: Uuid = sqlx::query_scalar("SELECT cursor_id FROM observation_snapshot_cursors WHERE snapshot_id=$1 AND through=$2")
            .bind(snapshot).bind(through).fetch_one(&mut *tx).await?;
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        tx.commit().await?;
        Ok(SnapshotPage {
            snapshot_id: snapshot,
            observations: rows.into_iter().map(|r| r.0).collect(),
            cursor,
            complete: through == count,
            committed_high_water: high_water as u64,
            recovery_epoch: claims.recovery_epoch,
        })
    }

    pub async fn ack_snapshot(
        &self,
        snapshot: Uuid,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<CommandResult> {
        let c: Command = Self::decode(body)?;
        let ack: AckSnapshot = c.payload()?;
        id(&ack.durable_receipt_id)?;
        if c.operation != "ack-snapshot"
            || ack.snapshot_id != snapshot
            || c.resource.reference != "observations"
            || c.resource.revision != "1"
        {
            return Err(Fault::Denied.into());
        }
        let mut tx = self.begin().await?;
        let (registration, claims) = self
            .authorize_command(
                &mut tx,
                &c,
                &SignedRequest {
                    headers: &headers,
                    body,
                },
                &format!("/integration/v1/observation-snapshots/{snapshot}/ack"),
                None,
                auth::INVOCATION,
            )
            .await?;
        self.service_scope(&registration, &claims)?;
        let (high_water, count) =
            Self::snapshot_boundary(&mut tx, snapshot, &c.consumer_id, &claims).await?;
        let through: i64 = sqlx::query_scalar("SELECT through FROM observation_snapshot_cursors WHERE cursor_id=$1 AND snapshot_id=$2")
            .bind(ack.cursor).bind(snapshot).fetch_optional(&mut *tx).await?.ok_or(Fault::Denied)?;
        if through != count {
            return Err(Fault::Conflict.into());
        }
        if let Some(result) = Self::replay(&mut tx, &c).await? {
            tx.commit().await?;
            return Ok(result);
        }
        let digest = sha256(format!("snapshot:{snapshot}").as_bytes());
        let existing: Option<String> = sqlx::query_scalar("SELECT durable_receipt_id FROM observation_receipts WHERE consumer_id=$1 AND cursor_sha256=$2")
            .bind(&c.consumer_id).bind(&digest).fetch_optional(&mut *tx).await?;
        match existing {
            Some(receipt) if receipt != ack.durable_receipt_id => {
                return Err(Fault::Conflict.into())
            }
            Some(_) => (),
            None => {
                let reused: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM observation_receipts WHERE consumer_id=$1 AND durable_receipt_id=$2)")
                    .bind(&c.consumer_id).bind(&ack.durable_receipt_id).fetch_one(&mut *tx).await?;
                if reused {
                    return Err(Fault::Conflict.into());
                }
                Self::observation_offset(&mut tx, &c.consumer_id, &claims).await?;
                sqlx::query("INSERT INTO observation_receipts(consumer_id,module_id,context_domain,recovery_epoch,cursor_sha256,durable_receipt_id,acknowledged) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64).bind(digest).bind(&ack.durable_receipt_id).bind(high_water).execute(&mut *tx).await?;
                sqlx::query("UPDATE observation_offsets SET acknowledged=GREATEST(acknowledged,$5) WHERE consumer_id=$1 AND module_id=$2 AND context_domain=$3 AND recovery_epoch=$4")
                    .bind(&c.consumer_id).bind(&claims.module_id).bind(&claims.context_domain).bind(claims.recovery_epoch as i64).bind(high_water).execute(&mut *tx).await?;
            }
        }
        claims.fresh(Self::now(&mut tx).await?.timestamp())?;
        let result = Self::remember(&mut tx,(&c,&claims),ack.durable_receipt_id.clone(),Execution::Completed,1,
            json!({"snapshot_id":snapshot,"acknowledged":high_water,"durable_receipt_id":ack.durable_receipt_id,"purged":false})).await?;
        tx.commit().await?;
        Ok(result)
    }
}
