-- Sequence allocation and event insertion share the committing transaction.
CREATE TABLE observation_counters (
    consumer_id text PRIMARY KEY REFERENCES consumer_registry,
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence BETWEEN 0 AND 9007199254740991),
    retained_after bigint NOT NULL DEFAULT 0 CHECK (retained_after BETWEEN 0 AND next_sequence)
);
CREATE TABLE observations (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    module_id text NOT NULL,
    context_domain text NOT NULL,
    record jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id, sequence)
);
CREATE INDEX observation_scope ON observations(consumer_id,module_id,context_domain,sequence);
CREATE TRIGGER immutable_observations BEFORE UPDATE OR DELETE ON observations
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TABLE observation_offsets (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    module_id text NOT NULL,
    context_domain text NOT NULL,
    recovery_epoch bigint NOT NULL,
    acknowledged bigint NOT NULL DEFAULT 0 CHECK (acknowledged BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY(consumer_id,module_id,context_domain,recovery_epoch)
);
CREATE TABLE observation_receipts (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    module_id text NOT NULL,
    context_domain text NOT NULL,
    recovery_epoch bigint NOT NULL,
    cursor_sha256 text NOT NULL CHECK (cursor_sha256 ~ '^[0-9a-f]{64}$'),
    durable_receipt_id text NOT NULL,
    acknowledged bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id,cursor_sha256),
    UNIQUE(consumer_id,durable_receipt_id)
);
CREATE TRIGGER immutable_observation_receipts BEFORE UPDATE OR DELETE ON observation_receipts
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
-- Trusted gateway-only HMAC material. Never returned by a consumer/profile API.
CREATE TABLE observation_keys (
    key_id uuid PRIMARY KEY,
    secret bytea NOT NULL CHECK (octet_length(secret) = 32),
    active boolean NOT NULL,
    verify_until timestamptz
);
CREATE UNIQUE INDEX one_active_observation_key ON observation_keys(active) WHERE active;
INSERT INTO observation_keys(key_id,secret,active)
VALUES(gen_random_uuid(),decode(replace(gen_random_uuid()::text||gen_random_uuid()::text,'-',''),'hex'),true);
