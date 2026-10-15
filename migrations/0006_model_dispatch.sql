-- Immutable budget reservations remain unchanged. Only the trusted model gateway
-- may attest counting/dispatch/usage through independently signed invocations.
CREATE TABLE model_dispatches (
    reservation_id uuid PRIMARY KEY REFERENCES model_reservations(reservation_id),
    consumer_id text NOT NULL REFERENCES consumer_registry,
    root_task_id text NOT NULL,
    task_id text NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    request jsonb NOT NULL,
    pricing jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('unknown','settled','incident')),
    settlement jsonb,
    dispatched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatch_deadline timestamptz NOT NULL,
    settled_at timestamptz,
    CHECK ((state = 'unknown') = (settlement IS NULL)),
    CHECK ((state = 'unknown') = (settled_at IS NULL)),
    CHECK (dispatch_deadline > dispatched_at),
    FOREIGN KEY(consumer_id,root_task_id) REFERENCES task_roots(consumer_id,root_task_id),
    FOREIGN KEY(consumer_id,task_id) REFERENCES task_members(consumer_id,task_id)
);
CREATE INDEX unresolved_model_dispatch ON model_dispatches(consumer_id,root_task_id)
    WHERE state IN ('unknown','incident');
CREATE FUNCTION freeze_model_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.reservation_id,NEW.consumer_id,NEW.root_task_id,NEW.task_id,
           NEW.generation,NEW.request,NEW.pricing,NEW.dispatched_at,NEW.dispatch_deadline)
       IS DISTINCT FROM
       ROW(OLD.reservation_id,OLD.consumer_id,OLD.root_task_id,OLD.task_id,
           OLD.generation,OLD.request,OLD.pricing,OLD.dispatched_at,OLD.dispatch_deadline)
       OR OLD.state <> 'unknown' OR NEW.state NOT IN ('settled','incident') THEN
        RAISE EXCEPTION 'immutable model dispatch identity or terminal result';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_model_dispatch BEFORE UPDATE ON model_dispatches
    FOR EACH ROW EXECUTE FUNCTION freeze_model_dispatch();
CREATE TRIGGER no_delete_model_dispatch BEFORE DELETE ON model_dispatches
    FOR EACH ROW EXECUTE FUNCTION deny_history_mutation();
