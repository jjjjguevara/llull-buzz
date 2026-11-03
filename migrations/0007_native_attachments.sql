-- Exact original attachment bytes, scoped by the existing native intake owner.
-- No global hash address or cross-consumer blob lookup is introduced.
CREATE TABLE native_attachments (
    consumer_id text NOT NULL,
    source_id uuid NOT NULL,
    evidence_source_id text NOT NULL,
    evidence jsonb NOT NULL,
    byte_sha256 text NOT NULL CHECK(byte_sha256 ~ '^[0-9a-f]{64}$'),
    byte_length bigint NOT NULL CHECK(byte_length BETWEEN 0 AND 26214400),
    bytes bytea NOT NULL,
    origin_owner text NOT NULL,
    retained_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id, source_id, evidence_source_id),
    FOREIGN KEY(consumer_id, source_id) REFERENCES native_inputs(consumer_id, source_id),
    CHECK(octet_length(bytes) = byte_length),
    CHECK(encode(sha256(bytes), 'hex') = byte_sha256),
    CHECK(evidence->>'sha256' = byte_sha256),
    CHECK(evidence->>'source_id' = evidence_source_id),
    CHECK((evidence->>'size_bytes')::bigint = byte_length)
);
CREATE TRIGGER immutable_native_attachments BEFORE UPDATE OR DELETE ON native_attachments
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
