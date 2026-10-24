//! Lossless retained metadata identities. No original private body is admitted.
use super::{deny, json, relations, Result};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    relation: String,
    row_sha256: String,
    row_key: Vec<Box<RawValue>>,
    metadata: BTreeMap<String, Box<RawValue>>,
    #[serde(skip)]
    uncertainties: Vec<&'static str>,
}
fn extras(name: &str) -> &'static [&'static str] {
    match name {
        "consumer_registry" | "registration_history" => &[
            "registration_metadata",
            "registration_shape_valid",
            "modules_shape_valid",
            "original_registration_sha256",
        ],
        "enrollment_challenges" => &["original_requested_sha256", "original_challenge_sha256"],
        "enrollments" => &["original_proof_event_sha256"],
        "enrollment_history" => &[
            "record_metadata",
            "record_shape_valid",
            "original_record_sha256",
        ],
        "commands" => &["original_result_sha256"],
        "task_roots" => &[
            "state",
            "worker_shape_valid",
            "state_shape_valid",
            "original_record_sha256",
            "original_state_sha256",
        ],
        "task_members" => &["original_manifest_sha256"],
        "attempts" => &["original_request_bytes_sha256", "original_charge_sha256"],
        "model_reservations" => &["original_reservation_sha256", "original_charge_sha256"],
        "publications" => &["original_publication_sha256", "original_release_sha256"],
        "publication_scopes" => &["original_scope_sha256"],
        "publication_deliveries" => &["original_signed_event_sha256", "original_audience_sha256"],
        "admission_evidence" => &[
            "original_native_authorization_sha256",
            "original_invocation_jws_sha256",
            "original_registration_snapshot_sha256",
            "original_claims_sha256",
        ],
        "observations" | "observation_snapshot_entries" => &[
            "record_metadata",
            "record_shape_valid",
            "original_record_sha256",
        ],
        "observation_keys" => &["original_secret_sha256"],
        "native_inputs" => &["original_intake_sha256", "original_event_bytes_sha256"],
        _ => &[],
    }
}
impl Row {
    pub fn parse(raw: &[u8], expected: &str) -> Result<Self> {
        json::validate_raw(raw)?;
        let mut row: Self = serde_json::from_slice(raw).map_err(|_| deny("inventory_row_shape"))?;
        let relation = relations::relation(expected)?;
        if row.relation != expected || row.row_key.len() != relation.keys.len() {
            return Err(deny("inventory_row_identity"));
        }
        llull_buzz_wire::hash(&row.row_sha256)
            .map_err(|_| deny("inventory_original_commitment"))?;
        let mut allowed = relation.fields.iter().copied().collect::<BTreeSet<_>>();
        allowed.extend(extras(expected));
        if row.metadata.len() != allowed.len()
            || row
                .metadata
                .keys()
                .any(|key| !allowed.contains(key.as_str()))
        {
            return Err(deny("inventory_metadata_whitelist"));
        }
        for (index, key) in relation.keys.iter().enumerate() {
            let value = row
                .metadata
                .get(*key)
                .ok_or_else(|| deny("inventory_row_key"))?;
            if value.get() == "null" || value.get() != row.row_key[index].get() {
                return Err(deny("inventory_row_key"));
            }
        }
        for (key, value) in &row.metadata {
            if key.starts_with("original_") && key.ends_with("_sha256") && value.get() != "null" {
                let digest: String = serde_json::from_str(value.get())
                    .map_err(|_| deny("inventory_original_commitment"))?;
                llull_buzz_wire::hash(&digest)
                    .map_err(|_| deny("inventory_original_commitment"))?;
            }
            if key.ends_with("_shape_valid") {
                let valid: Option<bool> = serde_json::from_str(value.get())
                    .map_err(|_| deny("inventory_source_shape"))?;
                if valid != Some(true) {
                    // Retain the row/commitment and source marker, not an empty
                    // complete manifest or a silently discarded uncertain row.
                    row.uncertainties.push("inventory-original-shape-unknown");
                }
            }
        }
        for key in ["registration_metadata", "record_metadata", "state"] {
            if let Some(raw) = row.metadata.get(key) {
                let checked = match (expected, key) {
                    ("consumer_registry" | "registration_history", "registration_metadata") => {
                        serde_json::from_str::<RegistrationMetadata>(raw.get()).map(|_| ())
                    }
                    ("enrollment_history", "record_metadata") => {
                        serde_json::from_str::<EnrollmentMetadata>(raw.get()).map(|_| ())
                    }
                    ("observations" | "observation_snapshot_entries", "record_metadata") => {
                        serde_json::from_str::<ObservationMetadata>(raw.get()).map(|_| ())
                    }
                    ("task_roots", "state") => {
                        serde_json::from_str::<StateMetadata>(raw.get()).map(|_| ())
                    }
                    _ => continue,
                };
                if checked.is_err() {
                    row.uncertainties.push("inventory-original-type-unknown");
                }
            }
        }
        Ok(row)
    }
    pub fn identity(&self) -> Result<String> {
        #[derive(serde::Serialize)]
        enum Key {
            Text(String),
            Integer(i128),
        }
        let keys = self
            .row_key
            .iter()
            .map(|raw| {
                if raw.get().starts_with('"') {
                    serde_json::from_str::<String>(raw.get()).map(Key::Text)
                } else {
                    serde_json::from_str::<i128>(raw.get()).map(Key::Integer)
                }
                .map_err(|_| deny("inventory_key_type"))
            })
            .collect::<Result<Vec<_>>>()?;
        serde_json::to_string(&keys).map_err(|_| deny("inventory_key_encoding"))
    }
    pub fn uncertainties(&self) -> &[&'static str] {
        &self.uncertainties
    }
    pub fn original_sha256(&self) -> &str {
        &self.row_sha256
    }
    pub(crate) fn text(&self, key: &str) -> Result<String> {
        serde_json::from_str(
            self.metadata
                .get(key)
                .ok_or_else(|| deny("inventory_binding_missing"))?
                .get(),
        )
        .map_err(|_| deny("inventory_binding_type"))
    }
    pub(crate) fn integer(&self, key: &str) -> Result<u64> {
        serde_json::from_str(
            self.metadata
                .get(key)
                .ok_or_else(|| deny("inventory_binding_missing"))?
                .get(),
        )
        .map_err(|_| deny("inventory_binding_type"))
    }
    pub(crate) fn same(&self, key: &str, other: &Self, other_key: &str) -> Result<()> {
        if self
            .metadata
            .get(key)
            .ok_or_else(|| deny("inventory_binding_missing"))?
            .get()
            != other
                .metadata
                .get(other_key)
                .ok_or_else(|| deny("inventory_binding_missing"))?
                .get()
        {
            return Err(deny("inventory_history_binding"));
        }
        Ok(())
    }
}
/// Lossless uniqueness; duplicate original keys are never deduplicated.
pub fn verify_unique(rows: &[Row]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row in rows {
        if !seen.insert((row.relation.as_str(), row.identity()?)) {
            return Err(deny("inventory_duplicate"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationMetadata {
    consumer_id: String,
    revision: u64,
    policy_revision: String,
    authority_epoch: u64,
    community_id: String,
    service_principal: String,
    service_public_key: String,
    enrollment_bot_key: String,
    enrollment_channel: String,
    modules: BTreeMap<String, crate::auth::ModulePolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentMetadata {
    enrollment_id: String,
    consumer_id: String,
    module_id: String,
    issuer: String,
    subject: String,
    native_key: String,
    revision: u64,
    authority_epoch: u64,
    active: bool,
    key_retired: bool,
    proof_event_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationMetadata {
    sequence: u64,
    operation: String,
    operation_id: String,
    execution: llull_buzz_wire::Execution,
    revision: u64,
    resource: llull_buzz_wire::Resource,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateMetadata {
    generation: u64,
    revision: u64,
    phase: llull_buzz_wire::Execution,
    worker: Option<llull_buzz_wire::Worker>,
    stop_new_work: bool,
}
impl Row {
    fn value<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        serde_json::from_str(
            self.metadata
                .get(key)
                .ok_or_else(|| deny("inventory_binding_missing"))?
                .get(),
        )
        .map_err(|_| deny("inventory_binding_type"))
    }
    fn optional_text(&self, key: &str) -> Result<Option<String>> {
        self.value(key)
    }
    fn embedded<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.value(key)
    }
}
fn find<'a>(rows: &'a [Row], keys: &[(&str, &str)]) -> Result<Option<&'a Row>> {
    let mut found = None;
    for row in rows {
        let matched = keys
            .iter()
            .map(|(key, value)| row.text(key).map(|actual| actual == *value))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|v| v);
        if matched && found.replace(row).is_some() {
            return Err(deny("inventory_duplicate_binding"));
        }
    }
    Ok(found)
}
/// Full metadata acquisition scope and cross-bindings. Retained historical rows
/// remain evidence even when their current-work row has lawfully disappeared.
/// Missing/uncertain current ancestry is explicitly partial, never deduplicated.
pub(crate) fn verify_complete(
    raw: &BTreeMap<String, Vec<Vec<u8>>>,
    profile: &super::authority::Profile,
    recovery_epoch: u64,
    budget: &mut super::clock::Budget,
) -> Result<Vec<String>> {
    if raw.len() != relations::RELATIONS.len()
        || relations::RELATIONS
            .iter()
            .any(|r| !raw.contains_key(r.name))
    {
        return Err(deny("inventory_history_scope"));
    }
    let mut parsed = BTreeMap::new();
    let mut gaps = BTreeSet::new();
    for relation in relations::RELATIONS {
        let rows = raw[relation.name]
            .iter()
            .map(|bytes| Row::parse(bytes, relation.name))
            .collect::<Result<Vec<_>>>()?;
        verify_unique(&rows)?;
        for row in &rows {
            for gap in row.uncertainties() {
                gaps.insert((*gap).to_owned());
            }
        }
        parsed.insert(relation.name, rows);
        budget.sample(super::clock::now())?;
    }
    let control = &parsed["provider_control"];
    if control.len() != 1
        || control[0].integer("singleton")? != 1
        || control[0].integer("recovery_epoch")? != recovery_epoch
        || control[0].text("activation")? != "foundation-only"
    {
        return Err(deny("inventory_epoch"));
    }
    let registry = &parsed["consumer_registry"];
    if registry.len() != profile.members.len() {
        return Err(deny("inventory_membership"));
    }
    for member in &profile.members {
        let row = find(registry, &[("consumer_id", &member.consumer_id)])?
            .ok_or_else(|| deny("inventory_membership"))?;
        let registration: RegistrationMetadata = row.embedded("registration_metadata")?;
        if row.text("registration_sha256")? != member.registration_sha256
            || registration.consumer_id != member.consumer_id
            || registration.revision != row.integer("revision")?
            || registration.service_principal != member.service_principal
            || registration
                .modules
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != member.modules.iter().cloned().collect::<BTreeSet<_>>()
        {
            return Err(deny("inventory_membership_binding"));
        }
        for identifier in [
            &registration.policy_revision,
            &registration.community_id,
            &registration.enrollment_channel,
        ] {
            llull_buzz_wire::id(identifier).map_err(|_| deny("inventory_registration_type"))?;
        }
        for hash in [
            &registration.service_public_key,
            &registration.enrollment_bot_key,
        ] {
            llull_buzz_wire::hash(hash).map_err(|_| deny("inventory_registration_type"))?;
        }
        if registration.authority_epoch == 0 {
            return Err(deny("inventory_registration_type"));
        }
        let revision = row.integer("revision")?;
        let history = parsed["registration_history"]
            .iter()
            .find(|h| {
                h.text("consumer_id").ok().as_deref() == Some(&member.consumer_id)
                    && h.integer("revision").ok() == Some(revision)
            })
            .ok_or_else(|| deny("inventory_registration_history"))?;
        row.same(
            "original_registration_sha256",
            history,
            "original_registration_sha256",
        )?;
        row.same("active", history, "active")?;
    }
    // All histories are retained, not just the current generation. A sequence
    // hole or a revision newer than current is a concrete source disagreement.
    let mut registration_revisions: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for row in &parsed["registration_history"] {
        let consumer = row.text("consumer_id")?;
        let revision = row.integer("revision")?;
        if let Ok(record) = row.embedded::<RegistrationMetadata>("registration_metadata") {
            if record.consumer_id != consumer || record.revision != revision {
                return Err(deny("inventory_registration_history_binding"));
            }
        }
        registration_revisions
            .entry(consumer.clone())
            .or_default()
            .push(revision);
        if let Some(current) = find(registry, &[("consumer_id", &consumer)])? {
            if revision > current.integer("revision")? {
                return Err(deny("inventory_registration_history"));
            }
        } else {
            gaps.insert("inventory-historical-registration-current-missing".into());
        }
    }
    for revisions in registration_revisions.values_mut() {
        revisions.sort_unstable();
        if revisions
            .iter()
            .enumerate()
            .any(|(i, r)| *r != i as u64 + 1)
        {
            return Err(deny("inventory_registration_history_gap"));
        }
    }
    for current in &parsed["enrollments"] {
        let id = current.text("enrollment_id")?;
        let revision = current.integer("revision")?;
        let matching = parsed["enrollment_history"]
            .iter()
            .find(|h| {
                h.text("enrollment_id").ok().as_deref() == Some(&id)
                    && h.integer("revision").ok() == Some(revision)
            })
            .ok_or_else(|| deny("inventory_enrollment_history"))?;
        let binding: EnrollmentMetadata = matching.embedded("record_metadata")?;
        if binding.enrollment_id != id
            || binding.revision != revision
            || binding.consumer_id != current.text("consumer_id")?
            || binding.module_id != current.text("module_id")?
            || binding.issuer != current.text("issuer")?
            || binding.subject != current.text("subject")?
            || binding.native_key != current.text("native_key")?
            || binding.authority_epoch != current.integer("authority_epoch")?
            || binding.active != current.value::<bool>("active")?
            || binding.key_retired != current.value::<bool>("key_retired")?
            || binding.proof_event_id != current.text("proof_event_id")?
            || binding.created_at != current.value::<chrono::DateTime<chrono::Utc>>("created_at")?
        {
            return Err(deny("inventory_enrollment_history_binding"));
        }
    }
    // The selected writer creates revision 1 and appends each +1 revision and
    // authority epoch. Retaining only the current row cannot prove that chain.
    let mut enrollment_chains: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for row in &parsed["enrollment_history"] {
        enrollment_chains
            .entry(row.text("enrollment_id")?)
            .or_default()
            .push(row);
    }
    for (id, chain) in &mut enrollment_chains {
        chain.sort_by_key(|row| row.integer("revision").unwrap_or(0));
        let current = find(&parsed["enrollments"], &[("enrollment_id", id)])?;
        if current.is_none() {
            gaps.insert("inventory-historical-enrollment-current-missing".into());
        }
        let mut previous: Option<EnrollmentMetadata> = None;
        for (index, row) in chain.iter().enumerate() {
            let revision = row.integer("revision")?;
            if revision != index as u64 + 1
                || current.is_some_and(|c| c.integer("revision").map_or(true, |r| revision > r))
            {
                return Err(deny("inventory_enrollment_history_gap"));
            }
            let record: EnrollmentMetadata = row.embedded("record_metadata")?;
            if record.enrollment_id != *id
                || record.revision != revision
                || record.authority_epoch == 0
                || (record.active && record.key_retired)
            {
                return Err(deny("inventory_enrollment_history_binding"));
            }
            let action = row.text("action")?;
            if let Some(prior) = &previous {
                if record.consumer_id != prior.consumer_id
                    || record.module_id != prior.module_id
                    || record.issuer != prior.issuer
                    || record.subject != prior.subject
                    || record.native_key != prior.native_key
                    || record.proof_event_id != prior.proof_event_id
                    || record.created_at != prior.created_at
                    || prior.authority_epoch.checked_add(1) != Some(record.authority_epoch)
                    || prior.key_retired
                {
                    return Err(deny("inventory_enrollment_transition"));
                }
                let lawful = match action.as_str() {
                    "access-restored" => !prior.active && record.active && !record.key_retired,
                    "access-revoked" => prior.active && !record.active && !record.key_retired,
                    "key-retired" => !record.active && record.key_retired,
                    _ => false,
                };
                if !lawful {
                    return Err(deny("inventory_enrollment_transition"));
                }
            } else if action != "intended-key-proven" || !record.active || record.key_retired {
                return Err(deny("inventory_enrollment_transition"));
            }
            previous = Some(record);
            budget.sample(super::clock::now())?;
        }
        if let Some(current) = current {
            if chain.len() as u64 != current.integer("revision")? {
                return Err(deny("inventory_enrollment_history_gap"));
            }
        }
    }
    let roots = &parsed["task_roots"];
    let tasks = &parsed["task_members"];
    for task in tasks {
        let consumer = task.text("consumer_id")?;
        let root = task.text("root_task_id")?;
        if find(
            roots,
            &[("consumer_id", &consumer), ("root_task_id", &root)],
        )?
        .is_none()
        {
            gaps.insert("inventory-historical-task-current-missing".into());
        }
    }
    let mut effect_ids = BTreeSet::new();
    let mut unresolved_slots = BTreeSet::new();
    for attempt in &parsed["attempts"] {
        let consumer = attempt.text("consumer_id")?;
        let task = attempt.text("task_id")?;
        let root = attempt.text("root_task_id")?;
        let owner = attempt.text("effect_owner")?;
        let intent = attempt.text("effect_intent_id")?;
        let slot = attempt.text("slot_sha256")?;
        for hash in [&slot, &attempt.text("request_sha256")?] {
            llull_buzz_wire::hash(hash).map_err(|_| deny("inventory_attempt_binding"))?;
        }
        if attempt.integer("generation")? == 0
            || !effect_ids.insert((consumer.clone(), owner.clone(), intent))
        {
            return Err(deny("inventory_attempt_binding"));
        }
        if let Some(member) = find(tasks, &[("consumer_id", &consumer), ("task_id", &task)])? {
            attempt.same("root_task_id", member, "root_task_id")?;
        } else {
            gaps.insert("inventory-historical-attempt-task-missing".into());
        }
        if find(
            roots,
            &[("consumer_id", &consumer), ("root_task_id", &root)],
        )?
        .is_none()
        {
            gaps.insert("inventory-historical-attempt-root-missing".into());
        }
        attempt.same("request_sha256", attempt, "original_request_bytes_sha256")?;
        let state = attempt.text("state")?;
        let result = attempt.optional_text("result_ref")?;
        if !["pending", "effect-unknown", "completed", "denied"].contains(&state.as_str())
            || (state == "completed") != result.is_some()
        {
            return Err(deny("inventory_attempt_outcome"));
        }
        if ["pending", "effect-unknown"].contains(&state.as_str()) {
            if !unresolved_slots.insert((consumer, owner, slot)) {
                return Err(deny("inventory_unresolved_slot"));
            }
            gaps.insert("inventory-effect-outcome-unresolved".into());
        }
        // No requirement for an attempt after a claimed reservation: a process
        // may crash before dispatch. Its genuine uncertainty survives below.
        budget.sample(super::clock::now())?;
    }
    for reservation in &parsed["model_reservations"] {
        let consumer = reservation.text("consumer_id")?;
        let task = reservation.text("task_id")?;
        if let Some(member) = find(tasks, &[("consumer_id", &consumer), ("task_id", &task)])? {
            reservation.same("root_task_id", member, "root_task_id")?;
        } else {
            gaps.insert("inventory-historical-reservation-task-missing".into());
        }
        gaps.insert("inventory-model-reservation-outcome-unobserved".into());
    }
    for delivery in &parsed["publication_deliveries"] {
        let publication = delivery.text("publication_id")?;
        let original = find(&parsed["publications"], &[("publication_id", &publication)])?
            .ok_or_else(|| deny("inventory_delivery_publication"))?;
        delivery.same("consumer_id", original, "consumer_id")?;
        delivery.same("event_sha256", delivery, "original_signed_event_sha256")?;
        if !["pending", "unknown", "completed", "denied"]
            .contains(&delivery.text("state")?.as_str())
        {
            return Err(deny("inventory_delivery_outcome"));
        }
        if delivery.text("state")? != "completed" {
            gaps.insert("inventory-publication-delivery-unresolved".into());
        }
    }
    for scope in &parsed["publication_scopes"] {
        let id = scope.text("publication_id")?;
        if find(&parsed["publications"], &[("publication_id", &id)])?.is_none() {
            return Err(deny("inventory_publication_scope"));
        }
    }
    for registration in &parsed["intake_registrations"] {
        let source = registration.text("source_id")?;
        let consumer = registration.text("consumer_id")?;
        if find(
            &parsed["native_inputs"],
            &[("source_id", &source), ("consumer_id", &consumer)],
        )?
        .is_none()
        {
            return Err(deny("inventory_intake_binding"));
        }
    }
    for counter in &parsed["observation_counters"] {
        let consumer = counter.text("consumer_id")?;
        let next = counter.integer("next_sequence")?;
        let retained = counter.integer("retained_after")?;
        if retained > next {
            return Err(deny("inventory_observation_counter"));
        }
        let mut sequences = Vec::new();
        for row in &parsed["observations"] {
            if row.text("consumer_id")? == consumer {
                let sequence = row.integer("sequence")?;
                if sequence == 0 || sequence > next {
                    return Err(deny("inventory_observation_counter"));
                }
                if sequence > retained {
                    sequences.push(sequence);
                }
                let record: ObservationMetadata = row.embedded("record_metadata")?;
                if record.sequence != sequence
                    || record.resource.namespace != consumer
                    || record.revision == 0
                {
                    return Err(deny("inventory_observation_binding"));
                }
                let _ = (&record.operation, &record.operation_id, &record.execution);
            }
        }
        sequences.sort_unstable();
        if sequences.len() as u64 != next - retained
            || sequences
                .iter()
                .enumerate()
                .any(|(i, s)| *s != retained + i as u64 + 1)
        {
            return Err(deny("inventory_observation_history_gap"));
        }
        for relation in ["observation_offsets", "observation_receipts"] {
            for row in &parsed[relation] {
                if row.text("consumer_id")? == consumer && row.integer("acknowledged")? > next {
                    return Err(deny("inventory_observation_acknowledgement"));
                }
            }
        }
    }
    for snapshot in &parsed["observation_snapshots"] {
        let id = snapshot.text("snapshot_id")?;
        let high = snapshot.integer("high_water")?;
        let consumer = snapshot.text("consumer_id")?;
        let counter = find(
            &parsed["observation_counters"],
            &[("consumer_id", &consumer)],
        )?;
        let observations = parsed["observations"]
            .iter()
            .filter(|row| row.text("consumer_id").ok().as_deref() == Some(consumer.as_str()))
            .collect::<Vec<_>>();
        if let Some(counter) = counter {
            if high > counter.integer("next_sequence")? {
                return Err(deny("inventory_snapshot_high_water"));
            }
        } else if high != 0 || !observations.is_empty() {
            return Err(deny("inventory_snapshot_counter"));
        }
        // Snapshot creation selects the latest record per operation in this
        // exact scope, ordered by sequence, at the frozen original high-water.
        // A retained watermark does not by itself prove that older rows exist.
        let mut present = BTreeSet::new();
        let mut latest: BTreeMap<(String, String), (u64, String)> = BTreeMap::new();
        for row in observations {
            let sequence = row.integer("sequence")?;
            if sequence <= high {
                present.insert(sequence);
                if row.text("module_id")? == snapshot.text("module_id")?
                    && row.text("context_domain")? == snapshot.text("context_domain")?
                {
                    let record: ObservationMetadata = row.embedded("record_metadata")?;
                    let key = (record.operation, record.operation_id);
                    let candidate = (sequence, row.text("original_record_sha256")?);
                    if latest.get(&key).is_none_or(|old| old.0 < sequence) {
                        latest.insert(key, candidate);
                    }
                }
            }
        }
        let reconstruction_complete = present.len() as u64 == high
            && present
                .iter()
                .enumerate()
                .all(|(i, seq)| *seq == i as u64 + 1);
        let mut expected_entries = latest.into_values().collect::<Vec<_>>();
        expected_entries.sort_by_key(|entry| entry.0);
        let mut actual_entries = Vec::new();
        let mut ordinals = Vec::new();
        let mut operations = BTreeSet::new();
        for entry in &parsed["observation_snapshot_entries"] {
            if entry.text("snapshot_id")? == id {
                let ordinal = entry.integer("ordinal")?;
                let record: ObservationMetadata = entry.embedded("record_metadata")?;
                if record.sequence > high
                    || record.resource.namespace != consumer
                    || !operations.insert((record.operation, record.operation_id))
                {
                    return Err(deny("inventory_snapshot_binding"));
                }
                actual_entries.push((
                    ordinal,
                    record.sequence,
                    entry.text("original_record_sha256")?,
                ));
                ordinals.push(ordinal);
            }
        }
        ordinals.sort_unstable();
        if ordinals.iter().enumerate().any(|(i, o)| *o != i as u64 + 1) {
            return Err(deny("inventory_snapshot_ordinals"));
        }
        actual_entries.sort_by_key(|entry| entry.0);
        if reconstruction_complete {
            let actual = actual_entries
                .iter()
                .map(|(_, sequence, digest)| (*sequence, digest.clone()))
                .collect::<Vec<_>>();
            if actual != expected_entries {
                return Err(deny("inventory_snapshot_membership"));
            }
        } else {
            // Keep every original entry and its commitment. No count or EOF
            // invents a missing historical boundary when retention prevents proof.
            gaps.insert("inventory-snapshot-original-completeness-unproven".into());
        }
        if counter.is_none() && !actual_entries.is_empty() {
            return Err(deny("inventory_snapshot_counter"));
        }
        for cursor in &parsed["observation_snapshot_cursors"] {
            if cursor.text("snapshot_id")? == id
                && cursor.integer("through")? > ordinals.len() as u64
            {
                return Err(deny("inventory_snapshot_cursor"));
            }
        }
    }
    for relation in [
        "observation_snapshot_entries",
        "observation_snapshot_cursors",
    ] {
        for row in &parsed[relation] {
            let id = row.text("snapshot_id")?;
            if find(&parsed["observation_snapshots"], &[("snapshot_id", &id)])?.is_none() {
                return Err(deny("inventory_snapshot_parent"));
            }
        }
    }
    for row in &parsed["enrollment_history"] {
        if let Ok(binding) = row.embedded::<EnrollmentMetadata>("record_metadata") {
            if binding.enrollment_id != row.text("enrollment_id")?
                || binding.revision != row.integer("revision")?
            {
                return Err(deny("inventory_enrollment_history_binding"));
            }
        }
    }
    for relation in [
        "observations",
        "observation_offsets",
        "observation_receipts",
    ] {
        for row in &parsed[relation] {
            let consumer = row.text("consumer_id")?;
            if find(
                &parsed["observation_counters"],
                &[("consumer_id", &consumer)],
            )?
            .is_none()
            {
                return Err(deny("inventory_observation_counter_missing"));
            }
        }
    }
    for row in &parsed["native_inputs"] {
        row.same("event_sha256", row, "original_event_bytes_sha256")?;
    }
    for root in roots {
        if let Ok(state) = root.embedded::<StateMetadata>("state") {
            if state.generation == 0 || state.revision == 0 {
                return Err(deny("inventory_task_state"));
            }
            if let Some(worker) = state.worker {
                if worker.generation != state.generation {
                    return Err(deny("inventory_worker_generation"));
                }
            }
            let _ = (&state.phase, state.stop_new_work);
        }
    }
    budget.sample(super::clock::now())?;
    Ok(gaps.into_iter().collect())
}
