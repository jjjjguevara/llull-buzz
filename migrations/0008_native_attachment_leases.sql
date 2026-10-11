-- Bounded custody of exact, already-authorized EvidenceAccess assertions.
-- Neither release_ref nor this table is an independent source of authority.
CREATE TABLE native_attachment_leases (
    lease_id uuid PRIMARY KEY,
    consumer_id text NOT NULL,
    operation text NOT NULL CHECK(operation = 'lease-native-attachment'),
    intent_id text NOT NULL,
    source_id uuid NOT NULL,
    evidence_source_id text NOT NULL,
    byte_sha256 text NOT NULL CHECK(byte_sha256 ~ '^[0-9a-f]{64}$'),
    enrollment_id text NOT NULL REFERENCES enrollments(enrollment_id),
    enrollment_revision bigint NOT NULL CHECK(enrollment_revision > 0),
    binding_epoch bigint NOT NULL CHECK(binding_epoch > 0),
    native_key text NOT NULL CHECK(native_key ~ '^[0-9a-f]{64}$'),
    module_id text NOT NULL,
    context_domain text NOT NULL,
    request jsonb NOT NULL,
    claims jsonb NOT NULL,
    owner text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(consumer_id,operation,intent_id),
    FOREIGN KEY(consumer_id,source_id,evidence_source_id)
        REFERENCES native_attachments(consumer_id,source_id,evidence_source_id),
    CHECK(request->'evidence'->>'sha256' = byte_sha256),
    CHECK(request->'evidence'->>'source_id' = evidence_source_id),
    CHECK((request->>'source_id')::uuid = source_id),
    CHECK(request->>'enrollment_id' = enrollment_id),
    CHECK((request->>'enrollment_revision')::bigint = enrollment_revision),
    CHECK((request->>'expires_at')::timestamptz = expires_at),
    CHECK(claims->>'consumer_id' = consumer_id),
    CHECK(claims->>'operation' = operation),
    CHECK(claims->>'intent_id' = intent_id),
    CHECK(claims->>'module_id' = module_id),
    CHECK(claims->>'context_domain' = context_domain),
    CHECK(expires_at <= to_timestamp((claims->>'exp')::bigint)),
    CHECK(expires_at <= to_timestamp((claims->>'authority_checked_at')::bigint + 60)),
    CHECK(expires_at > created_at)
);
CREATE INDEX native_attachment_lease_lookup ON native_attachment_leases(byte_sha256,native_key,expires_at);
CREATE TRIGGER immutable_native_attachment_leases BEFORE UPDATE OR DELETE ON native_attachment_leases
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
