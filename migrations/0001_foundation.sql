-- Original llull-buzz provider metadata only. No consumer or native relay tables.
CREATE TABLE provider_control (
    singleton smallint PRIMARY KEY CHECK (singleton = 1),
    recovery_epoch bigint NOT NULL CHECK (recovery_epoch BETWEEN 1 AND 9007199254740991),
    activation text NOT NULL DEFAULT 'foundation-only' CHECK (activation = 'foundation-only')
);
INSERT INTO provider_control(singleton, recovery_epoch) VALUES (1, 1);

CREATE TABLE consumer_registry (
    consumer_id text PRIMARY KEY CHECK (length(consumer_id) BETWEEN 1 AND 255),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    registration jsonb NOT NULL,
    registration_sha256 text NOT NULL CHECK (registration_sha256 ~ '^[0-9a-f]{64}$'),
    active boolean NOT NULL DEFAULT true
);
CREATE TABLE resource_replays (
    scope text NOT NULL,
    event_id text NOT NULL CHECK (event_id ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(scope, event_id)
);
CREATE INDEX resource_replays_expiry ON resource_replays(expires_at);
CREATE TABLE assertion_replays (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    issuer text NOT NULL,
    jti text NOT NULL CHECK (length(jti) BETWEEN 1 AND 255),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(consumer_id, issuer, jti)
);

CREATE TABLE enrollment_challenges (
    enrollment_id text PRIMARY KEY,
    consumer_id text NOT NULL REFERENCES consumer_registry,
    requested jsonb NOT NULL,
    challenge text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    recovery_epoch bigint NOT NULL,
    registration_revision bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '5 minutes'),
    UNIQUE(consumer_id, enrollment_id)
);
CREATE TABLE enrollments (
    enrollment_id text PRIMARY KEY,
    consumer_id text NOT NULL REFERENCES consumer_registry,
    module_id text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    native_key text NOT NULL CHECK (native_key ~ '^[0-9a-f]{64}$'),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    authority_epoch bigint NOT NULL CHECK (authority_epoch BETWEEN 1 AND 9007199254740991),
    active boolean NOT NULL,
    key_retired boolean NOT NULL,
    proof_event_id text NOT NULL CHECK (proof_event_id ~ '^[0-9a-f]{64}$'),
    proof_event jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    CHECK (NOT (active AND key_retired)),
    UNIQUE(consumer_id, enrollment_id)
);
CREATE UNIQUE INDEX one_active_principal_module ON enrollments(consumer_id, module_id, issuer, subject) WHERE active;
CREATE UNIQUE INDEX one_active_key_module ON enrollments(consumer_id, module_id, native_key) WHERE active;
CREATE TABLE enrollment_history (
    enrollment_id text NOT NULL REFERENCES enrollments,
    revision bigint NOT NULL,
    record jsonb NOT NULL,
    action text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(enrollment_id, revision)
);

CREATE TABLE commands (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    operation text NOT NULL,
    intent_id text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id, operation, intent_id)
);
CREATE TABLE task_roots (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    root_task_id text NOT NULL,
    root_intent_id text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    enrollment_id text,
    record jsonb NOT NULL,
    state jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    closed boolean NOT NULL DEFAULT false,
    PRIMARY KEY(consumer_id, root_task_id),
    UNIQUE(consumer_id, root_intent_id),
    FOREIGN KEY(consumer_id, enrollment_id) REFERENCES enrollments(consumer_id, enrollment_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE TABLE task_members (
    consumer_id text NOT NULL,
    task_id text NOT NULL,
    root_task_id text NOT NULL,
    manifest jsonb NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(consumer_id, task_id),
    FOREIGN KEY(consumer_id, root_task_id) REFERENCES task_roots(consumer_id, root_task_id)
);
CREATE TABLE attempts (
    attempt_id uuid PRIMARY KEY,
    consumer_id text NOT NULL,
    root_task_id text NOT NULL,
    task_id text NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    effect_owner text NOT NULL,
    effect_intent_id text NOT NULL,
    action text NOT NULL,
    slot_sha256 text NOT NULL CHECK (slot_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) <= 1048576),
    charge jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','effect-unknown','completed','denied')),
    result_ref text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz,
    CHECK ((state = 'completed') = (result_ref IS NOT NULL)),
    UNIQUE(consumer_id, effect_owner, effect_intent_id),
    FOREIGN KEY(consumer_id, root_task_id) REFERENCES task_roots(consumer_id, root_task_id),
    FOREIGN KEY(consumer_id, task_id) REFERENCES task_members(consumer_id, task_id)
);
-- A new request/effect ID cannot cover up uncertainty about the same target, even with a fresh resource revision.
CREATE UNIQUE INDEX unresolved_effect_slot ON attempts(consumer_id, effect_owner, slot_sha256)
    WHERE state IN ('pending','effect-unknown');
CREATE TABLE publications (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    intent_id text NOT NULL,
    publication_id uuid NOT NULL UNIQUE,
    release_ref text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    publication jsonb NOT NULL,
    release jsonb NOT NULL,
    enrollment_id text,
    recovery_epoch bigint NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state = 'pending'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id, intent_id),
    UNIQUE(consumer_id, release_ref),
    FOREIGN KEY(consumer_id, enrollment_id) REFERENCES enrollments(consumer_id, enrollment_id)
);
-- No native signed-event or dispatch table is implied: delivery remains unavailable.

CREATE FUNCTION deny_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'append-only provider history';
END;
$$;
CREATE TRIGGER immutable_enrollment_history BEFORE UPDATE OR DELETE ON enrollment_history
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_command_history BEFORE UPDATE OR DELETE ON commands
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_task_members BEFORE UPDATE OR DELETE ON task_members
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER immutable_publications BEFORE UPDATE OR DELETE ON publications
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();

CREATE FUNCTION freeze_root_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.consumer_id, NEW.root_task_id, NEW.root_intent_id, NEW.request_sha256,
           NEW.enrollment_id, NEW.record, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.consumer_id, OLD.root_task_id, OLD.root_intent_id, OLD.request_sha256,
           OLD.enrollment_id, OLD.record, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'immutable root identity';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_root_identity BEFORE UPDATE ON task_roots FOR EACH ROW EXECUTE FUNCTION freeze_root_identity();
CREATE FUNCTION freeze_attempt_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.attempt_id, NEW.consumer_id, NEW.root_task_id, NEW.task_id, NEW.generation,
           NEW.effect_owner, NEW.effect_intent_id, NEW.action, NEW.slot_sha256,
           NEW.request_sha256, NEW.request_bytes, NEW.charge, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.attempt_id, OLD.consumer_id, OLD.root_task_id, OLD.task_id, OLD.generation,
           OLD.effect_owner, OLD.effect_intent_id, OLD.action, OLD.slot_sha256,
           OLD.request_sha256, OLD.request_bytes, OLD.charge, OLD.created_at) THEN
        RAISE EXCEPTION 'immutable effect identity';
    END IF;
    IF OLD.state IN ('completed','denied') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal effect outcome';
    END IF;
    IF OLD.state = 'effect-unknown' AND NEW.state = 'pending' THEN
        RAISE EXCEPTION 'unknown effect cannot be redispatched';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_attempt_identity BEFORE UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION freeze_attempt_identity();

CREATE FUNCTION freeze_binding_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.enrollment_id, NEW.consumer_id, NEW.module_id, NEW.issuer, NEW.subject,
           NEW.native_key, NEW.proof_event_id, NEW.proof_event, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.enrollment_id, OLD.consumer_id, OLD.module_id, OLD.issuer, OLD.subject,
           OLD.native_key, OLD.proof_event_id, OLD.proof_event, OLD.created_at)
       OR NEW.revision <> OLD.revision + 1 OR NEW.authority_epoch <> OLD.authority_epoch + 1
       OR (OLD.key_retired AND NOT NEW.key_retired) THEN
        RAISE EXCEPTION 'immutable binding attribution or invalid epoch transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_binding_identity BEFORE UPDATE ON enrollments
    FOR EACH ROW EXECUTE FUNCTION freeze_binding_identity();

-- Budget-only records: no transition or worker can turn these into model dispatch.
CREATE TABLE model_reservations (
    reservation_id uuid PRIMARY KEY,
    consumer_id text NOT NULL,
    root_task_id text NOT NULL,
    task_id text NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    intent_id text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    reservation jsonb NOT NULL,
    charge jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(consumer_id,intent_id),
    FOREIGN KEY(consumer_id,root_task_id) REFERENCES task_roots(consumer_id,root_task_id),
    FOREIGN KEY(consumer_id,task_id) REFERENCES task_members(consumer_id,task_id)
);
CREATE TRIGGER immutable_model_reservation BEFORE UPDATE OR DELETE ON model_reservations
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER no_delete_roots BEFORE DELETE ON task_roots
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER no_delete_attempts BEFORE DELETE ON attempts
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TRIGGER no_delete_bindings BEFORE DELETE ON enrollments
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
-- Retention compaction is not exposed until it can preserve deduplication tombstones.


-- Immutable verification material. Access is restricted to the trusted control
-- role and encrypted storage/backups; never return these tokens in observations.
CREATE TABLE admission_evidence (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    issuer text NOT NULL,
    jti text NOT NULL,
    purpose text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    target_path text NOT NULL,
    method text NOT NULL,
    native_event_id text NOT NULL,
    native_authorization text NOT NULL CHECK (octet_length(native_authorization) <= 64000),
    invocation_jws text NOT NULL CHECK (octet_length(invocation_jws) <= 64000),
    registration_snapshot jsonb NOT NULL,
    claims jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id,issuer,jti)
);
CREATE TRIGGER immutable_admission_evidence BEFORE UPDATE OR DELETE ON admission_evidence
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TABLE registration_history (
    consumer_id text NOT NULL REFERENCES consumer_registry,
    revision bigint NOT NULL,
    active boolean NOT NULL,
    registration jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(consumer_id,revision)
);
CREATE TRIGGER immutable_registration_history BEFORE UPDATE OR DELETE ON registration_history
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
