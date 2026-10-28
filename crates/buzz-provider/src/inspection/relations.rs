//! Fixed provider-owned SQL projections; never a caller relation/filter registry.
use super::{deny, Result};
pub struct Relation {
    pub name: &'static str,
    pub fields: &'static [&'static str],
    pub keys: &'static [&'static str],
    sql: &'static str,
}
impl Relation {
    pub fn view_sql(&self) -> &'static str {
        self.sql
    }
}
pub static RELATIONS: &[Relation] = &[
    Relation {
        name: "provider_control",
        fields: &["singleton", "recovery_epoch", "activation"],
        keys: &["singleton"],
        sql: r###"CREATE VIEW buzz_inspection.v_provider_control WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.singleton) AS row_key, jsonb_build_object('singleton',r.singleton,'recovery_epoch',r.recovery_epoch,'activation',r.activation) AS metadata FROM public.provider_control AS r;"###,
    },
    Relation {
        name: "consumer_registry",
        fields: &["consumer_id", "revision", "registration_sha256", "active"],
        keys: &["consumer_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_consumer_registry WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'revision',r.revision,'registration_sha256',r.registration_sha256,'active',r.active,'registration_metadata',jsonb_build_object('consumer_id',CASE WHEN jsonb_typeof(r.registration->'consumer_id')='string' THEN r.registration->'consumer_id' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.registration->'revision')='number' THEN r.registration->'revision' ELSE NULL END,'policy_revision',CASE WHEN jsonb_typeof(r.registration->'policy_revision')='string' THEN r.registration->'policy_revision' ELSE NULL END,'authority_epoch',CASE WHEN jsonb_typeof(r.registration->'authority_epoch')='number' THEN r.registration->'authority_epoch' ELSE NULL END,'community_id',CASE WHEN jsonb_typeof(r.registration->'community_id')='string' THEN r.registration->'community_id' ELSE NULL END,'service_principal',CASE WHEN jsonb_typeof(r.registration->'service_principal')='string' THEN r.registration->'service_principal' ELSE NULL END,'service_public_key',CASE WHEN jsonb_typeof(r.registration->'service_public_key')='string' THEN r.registration->'service_public_key' ELSE NULL END,'enrollment_bot_key',CASE WHEN jsonb_typeof(r.registration->'enrollment_bot_key')='string' THEN r.registration->'enrollment_bot_key' ELSE NULL END,'enrollment_channel',CASE WHEN jsonb_typeof(r.registration->'enrollment_channel')='string' THEN r.registration->'enrollment_channel' ELSE NULL END,'modules',(SELECT coalesce(jsonb_object_agg(m.key,jsonb_build_object('actions',CASE WHEN jsonb_typeof(m.value->'actions')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'actions')='array' THEN m.value->'actions' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'actions' ELSE NULL END,'principal_issuers',CASE WHEN jsonb_typeof(m.value->'principal_issuers')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'principal_issuers')='array' THEN m.value->'principal_issuers' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'principal_issuers' ELSE NULL END,'context_domains',CASE WHEN jsonb_typeof(m.value->'context_domains')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'context_domains')='array' THEN m.value->'context_domains' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'context_domains' ELSE NULL END,'task_schemas',CASE WHEN jsonb_typeof(m.value->'task_schemas')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'task_schemas')='array' THEN m.value->'task_schemas' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'task_schemas' ELSE NULL END,'tools',(SELECT coalesce(jsonb_object_agg(t.key,jsonb_build_object('action',CASE WHEN jsonb_typeof(t.value->'action')='string' THEN t.value->'action' ELSE NULL END,'schema_sha256',CASE WHEN jsonb_typeof(t.value->'schema_sha256')='string' THEN t.value->'schema_sha256' ELSE NULL END,'effect_owner',CASE WHEN jsonb_typeof(t.value->'effect_owner')='string' THEN t.value->'effect_owner' ELSE NULL END,'requires_verdict',CASE WHEN jsonb_typeof(t.value->'requires_verdict')='boolean' THEN t.value->'requires_verdict' ELSE NULL END)),'{}'::jsonb) FROM jsonb_each(CASE WHEN jsonb_typeof(m.value->'tools')='object' THEN m.value->'tools' ELSE '{}'::jsonb END) t))),'{}'::jsonb) FROM jsonb_each(CASE WHEN jsonb_typeof(r.registration->'modules')='object' THEN r.registration->'modules' ELSE '{}'::jsonb END) m)),'modules_shape_valid',(jsonb_typeof(r.registration->'modules')='object' AND NOT EXISTS(SELECT 1 FROM jsonb_each(CASE WHEN jsonb_typeof(r.registration->'modules')='object' THEN r.registration->'modules' ELSE '{}'::jsonb END) m WHERE jsonb_typeof(m.value)<>'object' OR m.value-ARRAY['actions','principal_issuers','context_domains','task_schemas','tools']::text[]<>'{}'::jsonb OR jsonb_typeof(m.value->'tools') IS DISTINCT FROM 'object' OR EXISTS(SELECT 1 FROM jsonb_each(CASE WHEN jsonb_typeof(m.value->'tools')='object' THEN m.value->'tools' ELSE '{}'::jsonb END) t WHERE jsonb_typeof(t.value)<>'object' OR t.value-ARRAY['action','schema_sha256','effect_owner','requires_verdict']::text[]<>'{}'::jsonb))),'registration_shape_valid',(jsonb_typeof(r.registration)='object' AND (r.registration) - ARRAY['consumer_id','revision','policy_revision','authority_epoch','community_id','service_principal','service_public_key','enrollment_bot_key','enrollment_channel','issuer','audiences','verification_keys','modules','retention','pricing']::text[]='{}'::jsonb),'original_registration_sha256',encode(sha256(convert_to(r.registration::text,'UTF8')),'hex')) AS metadata FROM public.consumer_registry AS r;"###,
    },
    Relation {
        name: "registration_history",
        fields: &["consumer_id", "revision", "active", "recorded_at"],
        keys: &["consumer_id", "revision"],
        sql: r###"CREATE VIEW buzz_inspection.v_registration_history WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.revision) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'revision',r.revision,'active',r.active,'recorded_at',r.recorded_at,'registration_metadata',jsonb_build_object('consumer_id',CASE WHEN jsonb_typeof(r.registration->'consumer_id')='string' THEN r.registration->'consumer_id' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.registration->'revision')='number' THEN r.registration->'revision' ELSE NULL END,'policy_revision',CASE WHEN jsonb_typeof(r.registration->'policy_revision')='string' THEN r.registration->'policy_revision' ELSE NULL END,'authority_epoch',CASE WHEN jsonb_typeof(r.registration->'authority_epoch')='number' THEN r.registration->'authority_epoch' ELSE NULL END,'community_id',CASE WHEN jsonb_typeof(r.registration->'community_id')='string' THEN r.registration->'community_id' ELSE NULL END,'service_principal',CASE WHEN jsonb_typeof(r.registration->'service_principal')='string' THEN r.registration->'service_principal' ELSE NULL END,'service_public_key',CASE WHEN jsonb_typeof(r.registration->'service_public_key')='string' THEN r.registration->'service_public_key' ELSE NULL END,'enrollment_bot_key',CASE WHEN jsonb_typeof(r.registration->'enrollment_bot_key')='string' THEN r.registration->'enrollment_bot_key' ELSE NULL END,'enrollment_channel',CASE WHEN jsonb_typeof(r.registration->'enrollment_channel')='string' THEN r.registration->'enrollment_channel' ELSE NULL END,'modules',(SELECT coalesce(jsonb_object_agg(m.key,jsonb_build_object('actions',CASE WHEN jsonb_typeof(m.value->'actions')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'actions')='array' THEN m.value->'actions' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'actions' ELSE NULL END,'principal_issuers',CASE WHEN jsonb_typeof(m.value->'principal_issuers')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'principal_issuers')='array' THEN m.value->'principal_issuers' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'principal_issuers' ELSE NULL END,'context_domains',CASE WHEN jsonb_typeof(m.value->'context_domains')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'context_domains')='array' THEN m.value->'context_domains' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'context_domains' ELSE NULL END,'task_schemas',CASE WHEN jsonb_typeof(m.value->'task_schemas')='array' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.value->'task_schemas')='array' THEN m.value->'task_schemas' ELSE '[]'::jsonb END) item WHERE jsonb_typeof(item)<>'string') THEN m.value->'task_schemas' ELSE NULL END,'tools',(SELECT coalesce(jsonb_object_agg(t.key,jsonb_build_object('action',CASE WHEN jsonb_typeof(t.value->'action')='string' THEN t.value->'action' ELSE NULL END,'schema_sha256',CASE WHEN jsonb_typeof(t.value->'schema_sha256')='string' THEN t.value->'schema_sha256' ELSE NULL END,'effect_owner',CASE WHEN jsonb_typeof(t.value->'effect_owner')='string' THEN t.value->'effect_owner' ELSE NULL END,'requires_verdict',CASE WHEN jsonb_typeof(t.value->'requires_verdict')='boolean' THEN t.value->'requires_verdict' ELSE NULL END)),'{}'::jsonb) FROM jsonb_each(CASE WHEN jsonb_typeof(m.value->'tools')='object' THEN m.value->'tools' ELSE '{}'::jsonb END) t))),'{}'::jsonb) FROM jsonb_each(CASE WHEN jsonb_typeof(r.registration->'modules')='object' THEN r.registration->'modules' ELSE '{}'::jsonb END) m)),'modules_shape_valid',(jsonb_typeof(r.registration->'modules')='object' AND NOT EXISTS(SELECT 1 FROM jsonb_each(CASE WHEN jsonb_typeof(r.registration->'modules')='object' THEN r.registration->'modules' ELSE '{}'::jsonb END) m WHERE jsonb_typeof(m.value)<>'object' OR m.value-ARRAY['actions','principal_issuers','context_domains','task_schemas','tools']::text[]<>'{}'::jsonb OR jsonb_typeof(m.value->'tools') IS DISTINCT FROM 'object' OR EXISTS(SELECT 1 FROM jsonb_each(CASE WHEN jsonb_typeof(m.value->'tools')='object' THEN m.value->'tools' ELSE '{}'::jsonb END) t WHERE jsonb_typeof(t.value)<>'object' OR t.value-ARRAY['action','schema_sha256','effect_owner','requires_verdict']::text[]<>'{}'::jsonb))),'registration_shape_valid',(jsonb_typeof(r.registration)='object' AND (r.registration) - ARRAY['consumer_id','revision','policy_revision','authority_epoch','community_id','service_principal','service_public_key','enrollment_bot_key','enrollment_channel','issuer','audiences','verification_keys','modules','retention','pricing']::text[]='{}'::jsonb),'original_registration_sha256',encode(sha256(convert_to(r.registration::text,'UTF8')),'hex')) AS metadata FROM public.registration_history AS r;"###,
    },
    Relation {
        name: "resource_replays",
        fields: &["scope", "event_id", "expires_at"],
        keys: &["scope", "event_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_resource_replays WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.scope,r.event_id) AS row_key, jsonb_build_object('scope',r.scope,'event_id',r.event_id,'expires_at',r.expires_at) AS metadata FROM public.resource_replays AS r;"###,
    },
    Relation {
        name: "assertion_replays",
        fields: &["consumer_id", "issuer", "jti", "expires_at"],
        keys: &["consumer_id", "issuer", "jti"],
        sql: r###"CREATE VIEW buzz_inspection.v_assertion_replays WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.issuer,r.jti) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'issuer',r.issuer,'jti',r.jti,'expires_at',r.expires_at) AS metadata FROM public.assertion_replays AS r;"###,
    },
    Relation {
        name: "enrollment_challenges",
        fields: &[
            "enrollment_id",
            "consumer_id",
            "request_sha256",
            "issued_at",
            "recovery_epoch",
            "registration_revision",
            "expires_at",
            "consumed_at",
        ],
        keys: &["enrollment_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_enrollment_challenges WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.enrollment_id) AS row_key, jsonb_build_object('enrollment_id',r.enrollment_id,'consumer_id',r.consumer_id,'request_sha256',r.request_sha256,'issued_at',r.issued_at,'recovery_epoch',r.recovery_epoch,'registration_revision',r.registration_revision,'expires_at',r.expires_at,'consumed_at',r.consumed_at,'original_requested_sha256',encode(sha256(convert_to(r.requested::text,'UTF8')),'hex'),'original_challenge_sha256',encode(sha256(convert_to(r.challenge::text,'UTF8')),'hex')) AS metadata FROM public.enrollment_challenges AS r;"###,
    },
    Relation {
        name: "enrollments",
        fields: &[
            "enrollment_id",
            "consumer_id",
            "module_id",
            "issuer",
            "subject",
            "native_key",
            "revision",
            "authority_epoch",
            "active",
            "key_retired",
            "proof_event_id",
            "created_at",
        ],
        keys: &["enrollment_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_enrollments WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.enrollment_id) AS row_key, jsonb_build_object('enrollment_id',r.enrollment_id,'consumer_id',r.consumer_id,'module_id',r.module_id,'issuer',r.issuer,'subject',r.subject,'native_key',r.native_key,'revision',r.revision,'authority_epoch',r.authority_epoch,'active',r.active,'key_retired',r.key_retired,'proof_event_id',r.proof_event_id,'created_at',r.created_at,'original_proof_event_sha256',encode(sha256(convert_to(r.proof_event::text,'UTF8')),'hex')) AS metadata FROM public.enrollments AS r;"###,
    },
    Relation {
        name: "enrollment_history",
        fields: &["enrollment_id", "revision", "action", "recorded_at"],
        keys: &["enrollment_id", "revision"],
        sql: r###"CREATE VIEW buzz_inspection.v_enrollment_history WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.enrollment_id,r.revision) AS row_key, jsonb_build_object('enrollment_id',r.enrollment_id,'revision',r.revision,'action',r.action,'recorded_at',r.recorded_at,'record_metadata',jsonb_build_object('enrollment_id',CASE WHEN jsonb_typeof(r.record->'enrollment_id')='string' THEN r.record->'enrollment_id' ELSE NULL END,'consumer_id',CASE WHEN jsonb_typeof(r.record->'consumer_id')='string' THEN r.record->'consumer_id' ELSE NULL END,'module_id',CASE WHEN jsonb_typeof(r.record->'module_id')='string' THEN r.record->'module_id' ELSE NULL END,'issuer',CASE WHEN jsonb_typeof(r.record->'issuer')='string' THEN r.record->'issuer' ELSE NULL END,'subject',CASE WHEN jsonb_typeof(r.record->'subject')='string' THEN r.record->'subject' ELSE NULL END,'native_key',CASE WHEN jsonb_typeof(r.record->'native_key')='string' THEN r.record->'native_key' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.record->'revision')='number' THEN r.record->'revision' ELSE NULL END,'authority_epoch',CASE WHEN jsonb_typeof(r.record->'authority_epoch')='number' THEN r.record->'authority_epoch' ELSE NULL END,'active',CASE WHEN jsonb_typeof(r.record->'active')='boolean' THEN r.record->'active' ELSE NULL END,'key_retired',CASE WHEN jsonb_typeof(r.record->'key_retired')='boolean' THEN r.record->'key_retired' ELSE NULL END,'proof_event_id',CASE WHEN jsonb_typeof(r.record->'proof_event_id')='string' THEN r.record->'proof_event_id' ELSE NULL END,'created_at',CASE WHEN jsonb_typeof(r.record->'created_at')='string' THEN r.record->'created_at' ELSE NULL END),'record_shape_valid',(jsonb_typeof(r.record)='object' AND (r.record) - ARRAY['enrollment_id','consumer_id','module_id','issuer','subject','native_key','revision','authority_epoch','active','key_retired','proof_event_id','created_at','proof_event']::text[]='{}'::jsonb),'original_record_sha256',encode(sha256(convert_to(r.record::text,'UTF8')),'hex')) AS metadata FROM public.enrollment_history AS r;"###,
    },
    Relation {
        name: "commands",
        fields: &[
            "consumer_id",
            "operation",
            "intent_id",
            "request_sha256",
            "accepted_at",
        ],
        keys: &["consumer_id", "operation", "intent_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_commands WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.operation,r.intent_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'operation',r.operation,'intent_id',r.intent_id,'request_sha256',r.request_sha256,'accepted_at',r.accepted_at,'original_result_sha256',encode(sha256(convert_to(r.result::text,'UTF8')),'hex')) AS metadata FROM public.commands AS r;"###,
    },
    Relation {
        name: "task_roots",
        fields: &[
            "consumer_id",
            "root_task_id",
            "root_intent_id",
            "request_sha256",
            "enrollment_id",
            "created_at",
            "expires_at",
            "closed",
        ],
        keys: &["consumer_id", "root_task_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_task_roots WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.root_task_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'root_task_id',r.root_task_id,'root_intent_id',r.root_intent_id,'request_sha256',r.request_sha256,'enrollment_id',r.enrollment_id,'created_at',r.created_at,'expires_at',r.expires_at,'closed',r.closed,'state',jsonb_build_object('generation',CASE WHEN jsonb_typeof(r.state->'generation')='number' THEN r.state->'generation' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.state->'revision')='number' THEN r.state->'revision' ELSE NULL END,'phase',CASE WHEN jsonb_typeof(r.state->'phase')='string' THEN r.state->'phase' ELSE NULL END,'worker',CASE WHEN r.state->'worker'='null'::jsonb THEN 'null'::jsonb WHEN jsonb_typeof(r.state->'worker')='object' THEN jsonb_build_object('owner',CASE WHEN jsonb_typeof(r.state->'worker'->'owner')='string' THEN r.state->'worker'->'owner' ELSE NULL END,'generation',CASE WHEN jsonb_typeof(r.state->'worker'->'generation')='number' THEN r.state->'worker'->'generation' ELSE NULL END,'lease_until',CASE WHEN jsonb_typeof(r.state->'worker'->'lease_until')='string' THEN r.state->'worker'->'lease_until' ELSE NULL END) ELSE NULL END,'stop_new_work',CASE WHEN jsonb_typeof(r.state->'stop_new_work')='boolean' THEN r.state->'stop_new_work' ELSE NULL END),'worker_shape_valid',(r.state->'worker'='null'::jsonb OR (jsonb_typeof(r.state->'worker')='object' AND (r.state->'worker') - ARRAY['owner','generation','lease_until']::text[]='{}'::jsonb)),'state_shape_valid',(jsonb_typeof(r.state)='object' AND (r.state) - ARRAY['generation','revision','phase','spent','worker','stop_new_work']::text[]='{}'::jsonb),'original_record_sha256',encode(sha256(convert_to(r.record::text,'UTF8')),'hex'),'original_state_sha256',encode(sha256(convert_to(r.state::text,'UTF8')),'hex')) AS metadata FROM public.task_roots AS r;"###,
    },
    Relation {
        name: "task_members",
        fields: &["consumer_id", "task_id", "root_task_id", "request_sha256"],
        keys: &["consumer_id", "task_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_task_members WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.task_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'task_id',r.task_id,'root_task_id',r.root_task_id,'request_sha256',r.request_sha256,'original_manifest_sha256',encode(sha256(convert_to(r.manifest::text,'UTF8')),'hex')) AS metadata FROM public.task_members AS r;"###,
    },
    Relation {
        name: "attempts",
        fields: &[
            "attempt_id",
            "consumer_id",
            "root_task_id",
            "task_id",
            "generation",
            "effect_owner",
            "effect_intent_id",
            "action",
            "slot_sha256",
            "request_sha256",
            "state",
            "result_ref",
            "created_at",
            "dispatched_at",
        ],
        keys: &["attempt_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_attempts WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.attempt_id) AS row_key, jsonb_build_object('attempt_id',r.attempt_id,'consumer_id',r.consumer_id,'root_task_id',r.root_task_id,'task_id',r.task_id,'generation',r.generation,'effect_owner',r.effect_owner,'effect_intent_id',r.effect_intent_id,'action',r.action,'slot_sha256',r.slot_sha256,'request_sha256',r.request_sha256,'state',r.state,'result_ref',r.result_ref,'created_at',r.created_at,'dispatched_at',r.dispatched_at,'original_request_bytes_sha256',encode(sha256(r.request_bytes),'hex'),'original_charge_sha256',encode(sha256(convert_to(r.charge::text,'UTF8')),'hex')) AS metadata FROM public.attempts AS r;"###,
    },
    Relation {
        name: "model_reservations",
        fields: &[
            "reservation_id",
            "consumer_id",
            "root_task_id",
            "task_id",
            "generation",
            "intent_id",
            "request_sha256",
            "created_at",
        ],
        keys: &["reservation_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_model_reservations WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.reservation_id) AS row_key, jsonb_build_object('reservation_id',r.reservation_id,'consumer_id',r.consumer_id,'root_task_id',r.root_task_id,'task_id',r.task_id,'generation',r.generation,'intent_id',r.intent_id,'request_sha256',r.request_sha256,'created_at',r.created_at,'original_reservation_sha256',encode(sha256(convert_to(r.reservation::text,'UTF8')),'hex'),'original_charge_sha256',encode(sha256(convert_to(r.charge::text,'UTF8')),'hex')) AS metadata FROM public.model_reservations AS r;"###,
    },
    Relation {
        name: "publications",
        fields: &[
            "consumer_id",
            "intent_id",
            "publication_id",
            "release_ref",
            "request_sha256",
            "enrollment_id",
            "recovery_epoch",
            "state",
            "accepted_at",
        ],
        keys: &["consumer_id", "intent_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_publications WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.intent_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'intent_id',r.intent_id,'publication_id',r.publication_id,'release_ref',r.release_ref,'request_sha256',r.request_sha256,'enrollment_id',r.enrollment_id,'recovery_epoch',r.recovery_epoch,'state',r.state,'accepted_at',r.accepted_at,'original_publication_sha256',encode(sha256(convert_to(r.publication::text,'UTF8')),'hex'),'original_release_sha256',encode(sha256(convert_to(r.release::text,'UTF8')),'hex')) AS metadata FROM public.publications AS r;"###,
    },
    Relation {
        name: "publication_scopes",
        fields: &["publication_id", "root_task_id"],
        keys: &["publication_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_publication_scopes WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.publication_id) AS row_key, jsonb_build_object('publication_id',r.publication_id,'root_task_id',r.root_task_id,'original_scope_sha256',encode(sha256(convert_to(r.scope::text,'UTF8')),'hex')) AS metadata FROM public.publication_scopes AS r;"###,
    },
    Relation {
        name: "publication_deliveries",
        fields: &[
            "publication_id",
            "consumer_id",
            "module_id",
            "context_domain",
            "owner",
            "native_event_id",
            "event_sha256",
            "state",
            "revision",
            "created_at",
            "dispatched_at",
            "completed_at",
        ],
        keys: &["publication_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_publication_deliveries WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.publication_id) AS row_key, jsonb_build_object('publication_id',r.publication_id,'consumer_id',r.consumer_id,'module_id',r.module_id,'context_domain',r.context_domain,'owner',r.owner,'native_event_id',r.native_event_id,'event_sha256',r.event_sha256,'state',r.state,'revision',r.revision,'created_at',r.created_at,'dispatched_at',r.dispatched_at,'completed_at',r.completed_at,'original_signed_event_sha256',encode(sha256(r.signed_event),'hex'),'original_audience_sha256',encode(sha256(convert_to(r.audience::text,'UTF8')),'hex')) AS metadata FROM public.publication_deliveries AS r;"###,
    },
    Relation {
        name: "admission_evidence",
        fields: &[
            "consumer_id",
            "issuer",
            "jti",
            "purpose",
            "request_sha256",
            "target_path",
            "method",
            "native_event_id",
            "recorded_at",
        ],
        keys: &["consumer_id", "issuer", "jti"],
        sql: r###"CREATE VIEW buzz_inspection.v_admission_evidence WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.issuer,r.jti) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'issuer',r.issuer,'jti',r.jti,'purpose',r.purpose,'request_sha256',r.request_sha256,'target_path',r.target_path,'method',r.method,'native_event_id',r.native_event_id,'recorded_at',r.recorded_at,'original_native_authorization_sha256',encode(sha256(convert_to(r.native_authorization::text,'UTF8')),'hex'),'original_invocation_jws_sha256',encode(sha256(convert_to(r.invocation_jws::text,'UTF8')),'hex'),'original_registration_snapshot_sha256',encode(sha256(convert_to(r.registration_snapshot::text,'UTF8')),'hex'),'original_claims_sha256',encode(sha256(convert_to(r.claims::text,'UTF8')),'hex')) AS metadata FROM public.admission_evidence AS r;"###,
    },
    Relation {
        name: "observation_counters",
        fields: &["consumer_id", "next_sequence", "retained_after"],
        keys: &["consumer_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_counters WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'next_sequence',r.next_sequence,'retained_after',r.retained_after) AS metadata FROM public.observation_counters AS r;"###,
    },
    Relation {
        name: "observations",
        fields: &[
            "consumer_id",
            "sequence",
            "module_id",
            "context_domain",
            "recorded_at",
        ],
        keys: &["consumer_id", "sequence"],
        sql: r###"CREATE VIEW buzz_inspection.v_observations WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.sequence) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'sequence',r.sequence,'module_id',r.module_id,'context_domain',r.context_domain,'recorded_at',r.recorded_at,'record_metadata',jsonb_build_object('sequence',CASE WHEN jsonb_typeof(r.record->'sequence')='number' THEN r.record->'sequence' ELSE NULL END,'operation',CASE WHEN jsonb_typeof(r.record->'operation')='string' THEN r.record->'operation' ELSE NULL END,'operation_id',CASE WHEN jsonb_typeof(r.record->'operation_id')='string' THEN r.record->'operation_id' ELSE NULL END,'execution',CASE WHEN jsonb_typeof(r.record->'execution')='string' THEN r.record->'execution' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.record->'revision')='number' THEN r.record->'revision' ELSE NULL END,'resource',jsonb_build_object('namespace',CASE WHEN jsonb_typeof(r.record->'resource'->'namespace')='string' THEN r.record->'resource'->'namespace' ELSE NULL END,'ref',CASE WHEN jsonb_typeof(r.record->'resource'->'ref')='string' THEN r.record->'resource'->'ref' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.record->'resource'->'revision')='string' THEN r.record->'resource'->'revision' ELSE NULL END)),'record_shape_valid',((jsonb_typeof(r.record)='object' AND (r.record) - ARRAY['sequence','operation','operation_id','execution','revision','resource']::text[]='{}'::jsonb) AND (jsonb_typeof(r.record->'resource')='object' AND (r.record->'resource') - ARRAY['namespace','ref','revision']::text[]='{}'::jsonb)),'original_record_sha256',encode(sha256(convert_to(r.record::text,'UTF8')),'hex')) AS metadata FROM public.observations AS r;"###,
    },
    Relation {
        name: "observation_offsets",
        fields: &[
            "consumer_id",
            "module_id",
            "context_domain",
            "recovery_epoch",
            "acknowledged",
        ],
        keys: &[
            "consumer_id",
            "module_id",
            "context_domain",
            "recovery_epoch",
        ],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_offsets WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.module_id,r.context_domain,r.recovery_epoch) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'module_id',r.module_id,'context_domain',r.context_domain,'recovery_epoch',r.recovery_epoch,'acknowledged',r.acknowledged) AS metadata FROM public.observation_offsets AS r;"###,
    },
    Relation {
        name: "observation_receipts",
        fields: &[
            "consumer_id",
            "module_id",
            "context_domain",
            "recovery_epoch",
            "cursor_sha256",
            "durable_receipt_id",
            "acknowledged",
            "recorded_at",
        ],
        keys: &["consumer_id", "cursor_sha256"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_receipts WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.cursor_sha256) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'module_id',r.module_id,'context_domain',r.context_domain,'recovery_epoch',r.recovery_epoch,'cursor_sha256',r.cursor_sha256,'durable_receipt_id',r.durable_receipt_id,'acknowledged',r.acknowledged,'recorded_at',r.recorded_at) AS metadata FROM public.observation_receipts AS r;"###,
    },
    Relation {
        name: "observation_keys",
        fields: &["key_id", "active", "verify_until"],
        keys: &["key_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_keys WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.key_id) AS row_key, jsonb_build_object('key_id',r.key_id,'active',r.active,'verify_until',r.verify_until,'original_secret_sha256',encode(sha256(r.secret),'hex')) AS metadata FROM public.observation_keys AS r;"###,
    },
    Relation {
        name: "native_inputs",
        fields: &[
            "source_id",
            "consumer_id",
            "community_id",
            "event_id",
            "module_id",
            "context_domain",
            "channel_id",
            "enrollment_id",
            "enrollment_revision",
            "intake_sha256",
            "event_sha256",
            "accepted_at",
            "retain_until",
        ],
        keys: &["source_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_native_inputs WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.source_id) AS row_key, jsonb_build_object('source_id',r.source_id,'consumer_id',r.consumer_id,'community_id',r.community_id,'event_id',r.event_id,'module_id',r.module_id,'context_domain',r.context_domain,'channel_id',r.channel_id,'enrollment_id',r.enrollment_id,'enrollment_revision',r.enrollment_revision,'intake_sha256',r.intake_sha256,'event_sha256',r.event_sha256,'accepted_at',r.accepted_at,'retain_until',r.retain_until,'original_intake_sha256',encode(sha256(convert_to(r.intake::text,'UTF8')),'hex'),'original_event_bytes_sha256',encode(sha256(r.event_bytes),'hex')) AS metadata FROM public.native_inputs AS r;"###,
    },
    Relation {
        name: "intake_registrations",
        fields: &[
            "consumer_id",
            "source_id",
            "durable_receipt_id",
            "registered_at",
        ],
        keys: &["consumer_id", "source_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_intake_registrations WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.source_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'source_id',r.source_id,'durable_receipt_id',r.durable_receipt_id,'registered_at',r.registered_at) AS metadata FROM public.intake_registrations AS r;"###,
    },
    Relation {
        name: "observation_snapshots",
        fields: &[
            "snapshot_id",
            "consumer_id",
            "module_id",
            "context_domain",
            "recovery_epoch",
            "high_water",
            "created_at",
            "expires_at",
        ],
        keys: &["snapshot_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_snapshots WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.snapshot_id) AS row_key, jsonb_build_object('snapshot_id',r.snapshot_id,'consumer_id',r.consumer_id,'module_id',r.module_id,'context_domain',r.context_domain,'recovery_epoch',r.recovery_epoch,'high_water',r.high_water,'created_at',r.created_at,'expires_at',r.expires_at) AS metadata FROM public.observation_snapshots AS r;"###,
    },
    Relation {
        name: "observation_snapshot_entries",
        fields: &["snapshot_id", "ordinal"],
        keys: &["snapshot_id", "ordinal"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_snapshot_entries WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.snapshot_id,r.ordinal) AS row_key, jsonb_build_object('snapshot_id',r.snapshot_id,'ordinal',r.ordinal,'record_metadata',jsonb_build_object('sequence',CASE WHEN jsonb_typeof(r.record->'sequence')='number' THEN r.record->'sequence' ELSE NULL END,'operation',CASE WHEN jsonb_typeof(r.record->'operation')='string' THEN r.record->'operation' ELSE NULL END,'operation_id',CASE WHEN jsonb_typeof(r.record->'operation_id')='string' THEN r.record->'operation_id' ELSE NULL END,'execution',CASE WHEN jsonb_typeof(r.record->'execution')='string' THEN r.record->'execution' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.record->'revision')='number' THEN r.record->'revision' ELSE NULL END,'resource',jsonb_build_object('namespace',CASE WHEN jsonb_typeof(r.record->'resource'->'namespace')='string' THEN r.record->'resource'->'namespace' ELSE NULL END,'ref',CASE WHEN jsonb_typeof(r.record->'resource'->'ref')='string' THEN r.record->'resource'->'ref' ELSE NULL END,'revision',CASE WHEN jsonb_typeof(r.record->'resource'->'revision')='string' THEN r.record->'resource'->'revision' ELSE NULL END)),'record_shape_valid',((jsonb_typeof(r.record)='object' AND (r.record) - ARRAY['sequence','operation','operation_id','execution','revision','resource']::text[]='{}'::jsonb) AND (jsonb_typeof(r.record->'resource')='object' AND (r.record->'resource') - ARRAY['namespace','ref','revision']::text[]='{}'::jsonb)),'original_record_sha256',encode(sha256(convert_to(r.record::text,'UTF8')),'hex')) AS metadata FROM public.observation_snapshot_entries AS r;"###,
    },
    Relation {
        name: "observation_snapshot_cursors",
        fields: &["cursor_id", "snapshot_id", "through"],
        keys: &["cursor_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_observation_snapshot_cursors WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.cursor_id) AS row_key, jsonb_build_object('cursor_id',r.cursor_id,'snapshot_id',r.snapshot_id,'through',r.through) AS metadata FROM public.observation_snapshot_cursors AS r;"###,
    },
    Relation {
        name: "model_dispatches",
        fields: &[
            "reservation_id",
            "consumer_id",
            "root_task_id",
            "task_id",
            "generation",
            "state",
            "dispatched_at",
            "dispatch_deadline",
            "settled_at",
        ],
        keys: &["reservation_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_model_dispatches WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.reservation_id) AS row_key, jsonb_build_object('reservation_id',r.reservation_id,'consumer_id',r.consumer_id,'root_task_id',r.root_task_id,'task_id',r.task_id,'generation',r.generation,'state',r.state,'dispatched_at',r.dispatched_at,'dispatch_deadline',r.dispatch_deadline,'settled_at',r.settled_at,'original_request_sha256',encode(sha256(convert_to(r.request::text,'UTF8')),'hex'),'original_pricing_sha256',encode(sha256(convert_to(r.pricing::text,'UTF8')),'hex'),'original_settlement_sha256',encode(sha256(convert_to(r.settlement::text,'UTF8')),'hex')) AS metadata FROM public.model_dispatches AS r;"###,
    },
    Relation {
        name: "native_attachments",
        fields: &[
            "consumer_id",
            "source_id",
            "evidence_source_id",
            "byte_sha256",
            "byte_length",
            "origin_owner",
            "retained_at",
        ],
        keys: &["consumer_id", "source_id", "evidence_source_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_native_attachments WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.source_id,r.evidence_source_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'source_id',r.source_id,'evidence_source_id',r.evidence_source_id,'byte_sha256',r.byte_sha256,'byte_length',r.byte_length,'origin_owner',r.origin_owner,'retained_at',r.retained_at,'original_evidence_sha256',encode(sha256(convert_to(r.evidence::text,'UTF8')),'hex'),'original_bytes_sha256',encode(sha256(r.bytes),'hex')) AS metadata FROM public.native_attachments AS r;"###,
    },
    Relation {
        name: "native_attachment_leases",
        fields: &[
            "lease_id",
            "consumer_id",
            "operation",
            "intent_id",
            "source_id",
            "evidence_source_id",
            "byte_sha256",
            "enrollment_id",
            "enrollment_revision",
            "binding_epoch",
            "native_key",
            "module_id",
            "context_domain",
            "owner",
            "expires_at",
            "created_at",
        ],
        keys: &["lease_id"],
        sql: r###"CREATE VIEW buzz_inspection.v_native_attachment_leases WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.lease_id) AS row_key, jsonb_build_object('lease_id',r.lease_id,'consumer_id',r.consumer_id,'operation',r.operation,'intent_id',r.intent_id,'source_id',r.source_id,'evidence_source_id',r.evidence_source_id,'byte_sha256',r.byte_sha256,'enrollment_id',r.enrollment_id,'enrollment_revision',r.enrollment_revision,'binding_epoch',r.binding_epoch,'native_key',r.native_key,'module_id',r.module_id,'context_domain',r.context_domain,'owner',r.owner,'expires_at',r.expires_at,'created_at',r.created_at,'original_request_sha256',encode(sha256(convert_to(r.request::text,'UTF8')),'hex'),'original_claims_sha256',encode(sha256(convert_to(r.claims::text,'UTF8')),'hex')) AS metadata FROM public.native_attachment_leases AS r;"###,
    },
];
pub fn relation(name: &str) -> Result<&'static Relation> {
    RELATIONS
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| deny("unknown_relation"))
}

pub(crate) fn implementation_sha256() -> String {
    // Path and length framing prevent cross-file byte-boundary ambiguity.
    let inputs: &[(&str, &[u8])] = &[
        ("inspection/mod.rs", include_bytes!("mod.rs")),
        ("inspection/authority.rs", include_bytes!("authority.rs")),
        ("inspection/clock.rs", include_bytes!("clock.rs")),
        ("inspection/json.rs", include_bytes!("json.rs")),
        ("inspection/relations.rs", include_bytes!("relations.rs")),
        ("inspection/files.rs", include_bytes!("files.rs")),
        ("inspection/acquire.rs", include_bytes!("acquire.rs")),
        ("inspection/catalog.rs", include_bytes!("catalog.rs")),
        ("inspection/history.rs", include_bytes!("history.rs")),
        ("inspection/port.rs", include_bytes!("port.rs")),
        ("inspection/standing.rs", include_bytes!("standing.rs")),
        ("inspection/receiver.rs", include_bytes!("receiver.rs")),
        ("native_custody.rs", include_bytes!("../native_custody.rs")),
        ("native_origin.rs", include_bytes!("../native_origin.rs")),
        ("publication.rs", include_bytes!("../publication.rs")),
        ("main.rs", include_bytes!("../main.rs")),
        ("ports.rs", include_bytes!("../ports.rs")),
        (
            "bin/buzz-inspection.rs",
            include_bytes!("../bin/buzz-inspection.rs"),
        ),
        ("auth.rs", include_bytes!("../auth.rs")),
        ("db.rs", include_bytes!("../db.rs")),
        ("tasks.rs", include_bytes!("../tasks.rs")),
        ("effects.rs", include_bytes!("../effects.rs")),
        ("model_dispatch.rs", include_bytes!("../model_dispatch.rs")),
        ("native_media.rs", include_bytes!("../native_media.rs")),
        ("provider/Cargo.toml", include_bytes!("../../Cargo.toml")),
        (
            "workspace/Cargo.toml",
            include_bytes!("../../../../Cargo.toml"),
        ),
        (
            "wire/Cargo.toml",
            include_bytes!("../../../buzz-wire/Cargo.toml"),
        ),
        ("Cargo.lock", include_bytes!("../../../../Cargo.lock")),
        (
            "0006_model_dispatch.sql",
            include_bytes!("../../../../migrations/0006_model_dispatch.sql").as_slice(),
        ),
        (
            "0007_native_attachments.sql",
            include_bytes!("../../../../migrations/0007_native_attachments.sql").as_slice(),
        ),
        (
            "0008_native_attachment_leases.sql",
            include_bytes!("../../../../migrations/0008_native_attachment_leases.sql").as_slice(),
        ),
        (
            "0009_private_metadata_inspection.sql",
            include_bytes!("../../../../migrations/0009_private_metadata_inspection.sql"),
        ),
        (
            "0010_private_authority_inspection.sql",
            include_bytes!("../../../../migrations/0010_private_authority_inspection.sql"),
        ),
        (
            "wire/lib.rs",
            include_bytes!("../../../buzz-wire/src/lib.rs"),
        ),
        (
            "wire/json.rs",
            include_bytes!("../../../buzz-wire/src/json.rs"),
        ),
        (
            "wire/task.rs",
            include_bytes!("../../../buzz-wire/src/task.rs"),
        ),
        (
            "wire/wire.rs",
            include_bytes!("../../../buzz-wire/src/wire.rs"),
        ),
    ];
    let mut custody = Vec::new();
    for (name, raw) in inputs {
        custody.extend_from_slice(&(name.len() as u64).to_be_bytes());
        custody.extend_from_slice(name.as_bytes());
        custody.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        custody.extend_from_slice(raw);
    }
    llull_buzz_wire::sha256(&custody)
}

/// Immutable selected migrations plus the forward metadata migration. No
/// installation receipt is invented by computing these source commitments.
pub(crate) fn migration_pins() -> std::collections::BTreeMap<String, String> {
    [
        (
            "0001_foundation.sql",
            include_bytes!("../../../../migrations/0001_foundation.sql").as_slice(),
        ),
        (
            "0002_observations.sql",
            include_bytes!("../../../../migrations/0002_observations.sql").as_slice(),
        ),
        (
            "0003_native_intake.sql",
            include_bytes!("../../../../migrations/0003_native_intake.sql").as_slice(),
        ),
        (
            "0004_publication_delivery.sql",
            include_bytes!("../../../../migrations/0004_publication_delivery.sql").as_slice(),
        ),
        (
            "0005_observation_snapshots.sql",
            include_bytes!("../../../../migrations/0005_observation_snapshots.sql").as_slice(),
        ),
        (
            "0006_model_dispatch.sql",
            include_bytes!("../../../../migrations/0006_model_dispatch.sql").as_slice(),
        ),
        (
            "0007_native_attachments.sql",
            include_bytes!("../../../../migrations/0007_native_attachments.sql").as_slice(),
        ),
        (
            "0008_native_attachment_leases.sql",
            include_bytes!("../../../../migrations/0008_native_attachment_leases.sql").as_slice(),
        ),
        (
            "0009_private_metadata_inspection.sql",
            include_bytes!("../../../../migrations/0009_private_metadata_inspection.sql")
                .as_slice(),
        ),
        (
            "0010_private_authority_inspection.sql",
            include_bytes!("../../../../migrations/0010_private_authority_inspection.sql")
                .as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, raw)| (name.into(), llull_buzz_wire::sha256(raw)))
    .collect()
}

#[cfg(test)]
mod authority_projection_tests {
    use super::*;
    #[test]
    fn authority_projection_forward_source_is_exact_closed_and_additive() {
        let forward = include_str!("../../../../migrations/0010_private_authority_inspection.sql");
        let old = include_str!("../../../../migrations/0009_private_metadata_inspection.sql");
        for name in [
            "model_dispatches",
            "native_attachments",
            "native_attachment_leases",
        ] {
            let relation = relation(name).unwrap();
            assert!(forward.contains(relation.view_sql()));
            assert!(!old.contains(relation.view_sql()));
            assert!(forward.contains(&format!(
                "GRANT SELECT ON public.{name} TO buzz_recovery_view_owner;"
            )));
            assert!(forward.contains(&format!(
                "REVOKE ALL ON buzz_inspection.v_{name} FROM PUBLIC;"
            )));
            assert!(forward.contains(&format!(
                "GRANT SELECT ON buzz_inspection.v_{name} TO buzz_recovery_inspector;"
            )));
        }
        assert!(!forward.contains("CREATE TABLE"));
        assert!(!forward.contains("INSERT INTO"));
        assert!(!forward.contains("UPDATE "));
        assert_eq!(migration_pins().len(), 10);
        assert_eq!(RELATIONS.len(), 30);
    }
}
