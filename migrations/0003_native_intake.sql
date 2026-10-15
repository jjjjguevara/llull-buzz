-- Original native identity is separate from the consumer's durable acceptance.
CREATE TABLE native_inputs (
    source_id uuid PRIMARY KEY,
    consumer_id text NOT NULL REFERENCES consumer_registry,
    community_id text NOT NULL,
    event_id text NOT NULL CHECK(event_id ~ '^[0-9a-f]{64}$'),
    module_id text NOT NULL,
    context_domain text NOT NULL,
    channel_id text NOT NULL,
    enrollment_id text NOT NULL REFERENCES enrollments,
    enrollment_revision bigint NOT NULL,
    intake jsonb NOT NULL,
    intake_sha256 text NOT NULL CHECK(intake_sha256 ~ '^[0-9a-f]{64}$'),
    event_bytes bytea NOT NULL CHECK(octet_length(event_bytes) <= 1048576),
    event_sha256 text NOT NULL CHECK(event_sha256 ~ '^[0-9a-f]{64}$'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retain_until timestamptz NOT NULL,
    UNIQUE(consumer_id,community_id,event_id),
    UNIQUE(consumer_id,source_id)
);
CREATE TABLE intake_registrations (
    consumer_id text NOT NULL,
    source_id uuid NOT NULL,
    durable_receipt_id text NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id,source_id),
    UNIQUE(consumer_id,durable_receipt_id),
    FOREIGN KEY(consumer_id,source_id) REFERENCES native_inputs(consumer_id,source_id)
);
CREATE TRIGGER immutable_native_inputs BEFORE UPDATE OR DELETE ON native_inputs
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_intake_registrations BEFORE UPDATE OR DELETE ON intake_registrations
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
