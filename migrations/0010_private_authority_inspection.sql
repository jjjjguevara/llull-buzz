-- Forward extension of the fixed private metadata inspection surface.
-- Existing 0001..0009 sources and ordinary application privileges are unchanged.
-- Only non-bearer, closed authority metadata and original body commitments are
-- exported. Raw requests, signed claims, prompts, prices and attachment bytes
-- remain inaccessible to the inspector. Run only through maintained migrations.

GRANT SELECT ON public.model_dispatches TO buzz_recovery_view_owner;
CREATE VIEW buzz_inspection.v_model_dispatches WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.reservation_id) AS row_key, jsonb_build_object('reservation_id',r.reservation_id,'consumer_id',r.consumer_id,'root_task_id',r.root_task_id,'task_id',r.task_id,'generation',r.generation,'state',r.state,'dispatched_at',r.dispatched_at,'dispatch_deadline',r.dispatch_deadline,'settled_at',r.settled_at,'original_request_sha256',encode(sha256(convert_to(r.request::text,'UTF8')),'hex'),'original_pricing_sha256',encode(sha256(convert_to(r.pricing::text,'UTF8')),'hex'),'original_settlement_sha256',encode(sha256(convert_to(r.settlement::text,'UTF8')),'hex')) AS metadata FROM public.model_dispatches AS r;
REVOKE ALL ON buzz_inspection.v_model_dispatches FROM PUBLIC;
GRANT SELECT ON buzz_inspection.v_model_dispatches TO buzz_recovery_inspector;
ALTER VIEW buzz_inspection.v_model_dispatches OWNER TO buzz_recovery_view_owner;

GRANT SELECT ON public.native_attachments TO buzz_recovery_view_owner;
CREATE VIEW buzz_inspection.v_native_attachments WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.consumer_id,r.source_id,r.evidence_source_id) AS row_key, jsonb_build_object('consumer_id',r.consumer_id,'source_id',r.source_id,'evidence_source_id',r.evidence_source_id,'byte_sha256',r.byte_sha256,'byte_length',r.byte_length,'origin_owner',r.origin_owner,'retained_at',r.retained_at,'original_evidence_sha256',encode(sha256(convert_to(r.evidence::text,'UTF8')),'hex'),'original_bytes_sha256',encode(sha256(r.bytes),'hex')) AS metadata FROM public.native_attachments AS r;
REVOKE ALL ON buzz_inspection.v_native_attachments FROM PUBLIC;
GRANT SELECT ON buzz_inspection.v_native_attachments TO buzz_recovery_inspector;
ALTER VIEW buzz_inspection.v_native_attachments OWNER TO buzz_recovery_view_owner;

GRANT SELECT ON public.native_attachment_leases TO buzz_recovery_view_owner;
CREATE VIEW buzz_inspection.v_native_attachment_leases WITH (security_barrier = true) AS SELECT encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') AS row_sha256, jsonb_build_array(r.lease_id) AS row_key, jsonb_build_object('lease_id',r.lease_id,'consumer_id',r.consumer_id,'operation',r.operation,'intent_id',r.intent_id,'source_id',r.source_id,'evidence_source_id',r.evidence_source_id,'byte_sha256',r.byte_sha256,'enrollment_id',r.enrollment_id,'enrollment_revision',r.enrollment_revision,'binding_epoch',r.binding_epoch,'native_key',r.native_key,'module_id',r.module_id,'context_domain',r.context_domain,'owner',r.owner,'expires_at',r.expires_at,'created_at',r.created_at,'original_request_sha256',encode(sha256(convert_to(r.request::text,'UTF8')),'hex'),'original_claims_sha256',encode(sha256(convert_to(r.claims::text,'UTF8')),'hex')) AS metadata FROM public.native_attachment_leases AS r;
REVOKE ALL ON buzz_inspection.v_native_attachment_leases FROM PUBLIC;
GRANT SELECT ON buzz_inspection.v_native_attachment_leases TO buzz_recovery_inspector;
ALTER VIEW buzz_inspection.v_native_attachment_leases OWNER TO buzz_recovery_view_owner;
