-- Admission remains immutable. Delivery has its own monotonic durable state.
CREATE TABLE publication_scopes (
    publication_id uuid PRIMARY KEY REFERENCES publications(publication_id),
    scope jsonb NOT NULL,
    root_task_id text
);
CREATE TRIGGER immutable_publication_scope BEFORE UPDATE OR DELETE ON publication_scopes
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
CREATE TABLE publication_deliveries (
    publication_id uuid PRIMARY KEY REFERENCES publications(publication_id),
    consumer_id text NOT NULL REFERENCES consumer_registry,
    module_id text NOT NULL,
    context_domain text NOT NULL,
    owner text NOT NULL,
    native_event_id text NOT NULL UNIQUE CHECK(native_event_id ~ '^[0-9a-f]{64}$'),
    signed_event bytea NOT NULL CHECK(octet_length(signed_event)<=1048576),
    event_sha256 text NOT NULL CHECK(event_sha256 ~ '^[0-9a-f]{64}$'),
    audience jsonb NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','unknown','completed','denied')),
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz,
    completed_at timestamptz
);
CREATE FUNCTION freeze_publication_delivery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.publication_id,NEW.consumer_id,NEW.module_id,NEW.context_domain,
           NEW.owner,NEW.native_event_id,NEW.signed_event,NEW.event_sha256,NEW.audience,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.publication_id,OLD.consumer_id,OLD.module_id,OLD.context_domain,
           OLD.owner,OLD.native_event_id,OLD.signed_event,OLD.event_sha256,OLD.audience,OLD.created_at)
       OR NEW.revision <> OLD.revision+1
       OR (OLD.state IN ('completed','denied'))
       OR (OLD.state='unknown' AND NEW.state NOT IN ('unknown','completed')) THEN
        RAISE EXCEPTION 'immutable publication identity or invalid transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_publication_delivery BEFORE UPDATE ON publication_deliveries
    FOR EACH ROW EXECUTE FUNCTION freeze_publication_delivery();
CREATE TRIGGER no_delete_publication_delivery BEFORE DELETE ON publication_deliveries
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
