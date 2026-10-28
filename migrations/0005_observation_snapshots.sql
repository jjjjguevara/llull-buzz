-- Frozen, content-minimal recovery views. A page cursor is a random server-side
-- handle, never an offset selected by the caller or independent read authority.
CREATE TABLE observation_snapshots (
    snapshot_id uuid PRIMARY KEY,
    consumer_id text NOT NULL REFERENCES consumer_registry,
    module_id text NOT NULL,
    context_domain text NOT NULL,
    recovery_epoch bigint NOT NULL,
    high_water bigint NOT NULL CHECK(high_water BETWEEN 0 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '1 day'
);
CREATE TABLE observation_snapshot_entries (
    snapshot_id uuid NOT NULL REFERENCES observation_snapshots,
    ordinal bigint NOT NULL CHECK(ordinal > 0),
    record jsonb NOT NULL,
    PRIMARY KEY(snapshot_id,ordinal)
);
CREATE TABLE observation_snapshot_cursors (
    cursor_id uuid PRIMARY KEY,
    snapshot_id uuid NOT NULL REFERENCES observation_snapshots,
    through bigint NOT NULL CHECK(through >= 0),
    UNIQUE(snapshot_id,through)
);
CREATE TRIGGER immutable_observation_snapshots BEFORE UPDATE OR DELETE ON observation_snapshots
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_observation_snapshot_entries BEFORE UPDATE OR DELETE ON observation_snapshot_entries
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_observation_snapshot_cursors BEFORE UPDATE OR DELETE ON observation_snapshot_cursors
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
