-- Public pre-enrollment relay custody only. No native conversation, publication,
-- enrollment binding or access change is created by accepting a challenge event.
CREATE TABLE enrollment_native_authentications (
    consumer_id text NOT NULL,
    enrollment_id text NOT NULL,
    nip42_event_id text NOT NULL CHECK (nip42_event_id ~ '^[0-9a-f]{64}$'),
    nip42_event jsonb NOT NULL,
    relay_url text NOT NULL CHECK (relay_url LIKE 'wss://%'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (consumer_id, enrollment_id, nip42_event_id),
    FOREIGN KEY (consumer_id, enrollment_id)
        REFERENCES enrollment_challenges (consumer_id, enrollment_id),
    CHECK (nip42_event->>'id' = nip42_event_id AND nip42_event->>'kind' = '22242'),
    CHECK (expires_at > received_at AND expires_at <= received_at + interval '5 minutes')
);
CREATE TRIGGER immutable_enrollment_native_authentications
    BEFORE UPDATE OR DELETE ON enrollment_native_authentications
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();

CREATE TABLE enrollment_native_proofs (
    consumer_id text NOT NULL,
    enrollment_id text PRIMARY KEY,
    module_id text NOT NULL,
    context_domain text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    native_event_id text NOT NULL CHECK (native_event_id ~ '^[0-9a-f]{64}$'),
    native_event jsonb NOT NULL,
    nip42_event_id text NOT NULL CHECK (nip42_event_id ~ '^[0-9a-f]{64}$'),
    nip42_event jsonb NOT NULL,
    relay_url text NOT NULL CHECK (relay_url LIKE 'wss://%'),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (consumer_id, enrollment_id)
        REFERENCES enrollment_challenges (consumer_id, enrollment_id),
    FOREIGN KEY (consumer_id, enrollment_id, nip42_event_id)
        REFERENCES enrollment_native_authentications (consumer_id, enrollment_id, nip42_event_id),
    UNIQUE (consumer_id, native_event_id),
    CHECK (native_event->>'id' = native_event_id AND native_event->>'kind' = '9'),
    CHECK (nip42_event->>'id' = nip42_event_id AND nip42_event->>'kind' = '22242'),
    CHECK (native_event->>'pubkey' = nip42_event->>'pubkey')
);
CREATE TRIGGER immutable_enrollment_native_proofs
    BEFORE UPDATE OR DELETE ON enrollment_native_proofs
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
