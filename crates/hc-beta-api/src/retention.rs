use crate::{error::ApiError, AppState};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RetentionReport {
    pub enqueued: u64,
    pub deleted: u64,
    pub failed: u64,
}

pub async fn sweep(state: &AppState) -> Result<RetentionReport, ApiError> {
    let mut enqueued = 0u64;
    enqueued += sqlx::query(
        "INSERT INTO beta_retention_deletions
             (deletion_id,tenant_id,object_key,resource_kind,resource_id,not_before)
         SELECT md5(c.object_key)::uuid,u.tenant_id,c.object_key,'trace',u.upload_id,now()
           FROM beta_uploads u JOIN beta_upload_chunks c ON c.upload_id=u.upload_id
          WHERE u.expires_at <= now() AND u.status IN ('pending','complete')
         ON CONFLICT (object_key) DO NOTHING",
    )
    .execute(&state.pool)
    .await?
    .rows_affected();
    enqueued += sqlx::query(
        "INSERT INTO beta_retention_deletions
             (deletion_id,tenant_id,object_key,resource_kind,resource_id,not_before)
         SELECT md5(proof_object_key)::uuid,tenant_id,proof_object_key,'proof',job_id,now()
           FROM beta_proof_jobs
          WHERE proof_object_key IS NOT NULL AND retention_expires_at <= now()
         ON CONFLICT (object_key) DO NOTHING",
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    let rows = sqlx::query(
        "SELECT deletion_id,object_key,resource_kind,resource_id
           FROM beta_retention_deletions
          WHERE deleted_at IS NULL AND not_before <= now()
          ORDER BY not_before FOR UPDATE SKIP LOCKED LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut deleted = 0u64;
    let mut failed = 0u64;
    for row in rows {
        let deletion_id: Uuid = row.get("deletion_id");
        let key: String = row.get("object_key");
        match state.object_store.delete(&key).await {
            Ok(()) => {
                sqlx::query(
                    "UPDATE beta_retention_deletions SET deleted_at=now(),last_error=NULL
                      WHERE deletion_id=$1",
                )
                .bind(deletion_id)
                .execute(&state.pool)
                .await?;
                deleted += 1;
            }
            Err(error) => {
                sqlx::query(
                    "UPDATE beta_retention_deletions SET attempt=attempt+1,last_error=$2
                      WHERE deletion_id=$1",
                )
                .bind(deletion_id)
                .bind(error.to_string())
                .execute(&state.pool)
                .await?;
                failed += 1;
            }
        }
    }
    sqlx::query(
        "UPDATE beta_uploads u SET status='deleted',deleted_at=now()
          WHERE u.status <> 'deleted'
            AND EXISTS (SELECT 1 FROM beta_retention_deletions d WHERE d.resource_id=u.upload_id)
            AND NOT EXISTS (SELECT 1 FROM beta_retention_deletions d WHERE d.resource_id=u.upload_id AND d.deleted_at IS NULL)",
    )
    .execute(&state.pool).await?;
    sqlx::query(
        "UPDATE beta_proof_jobs j SET proof_object_key=NULL
          WHERE proof_object_key IS NOT NULL
            AND EXISTS (SELECT 1 FROM beta_retention_deletions d WHERE d.resource_id=j.job_id AND d.deleted_at IS NOT NULL)",
    )
    .execute(&state.pool).await?;
    Ok(RetentionReport {
        enqueued,
        deleted,
        failed,
    })
}
