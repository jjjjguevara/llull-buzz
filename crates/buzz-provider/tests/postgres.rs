//! Real PostgreSQL contract tests. Only the external consumer is doubled. No
//! in-memory repository, signature-verifier bypass or logical-clock injection.
//! Run via scripts/test-postgres.sh; never point at a non-disposable database.
use llull_buzz_provider::{auth::*,budget::Pricing,ports::*,wire::*,*};
use async_trait::async_trait;
use base64::{Engine,engine::general_purpose::STANDARD};
use chrono::{Duration as CD,Utc};
use p256::{ecdsa::SigningKey,pkcs8::{EncodePrivateKey,EncodePublicKey,LineEnding}};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sqlx::{PgPool,postgres::PgPoolOptions};
use std::{collections::{BTreeMap,BTreeSet},sync::{Mutex,atomic::{AtomicUsize,Ordering}},time::Duration};
use uuid::Uuid;

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)] struct SetLabel {label:String}
impl ConsumerCommand for SetLabel {
    const SCHEMA_ID:&'static str="synthetic.set-label.v1";
    const ACTION:&'static str="set-label";
    fn schema()->Value {json!({"type":"object","additionalProperties":false,"required":["label"],"properties":{"label":{"type":"string","minLength":1,"maxLength":80}}})}
    fn validate(&self)->llull_buzz_wire::Result<()> {if self.label.is_empty() || self.label.chars().count()>80 {Err(Fault::Invalid)}else{Ok(())}}
}
struct Signed {resource:String,assertion:String}
impl Signed {fn headers(&self)->Headers<'_> {Headers{authorization:&self.resource,invocation:&self.assertion}}}
struct Rig {p:Provider,pool:PgPool,registration:Registration,key:nostr::Keys,signer:jsonwebtoken::EncodingKey,browser:BrowserAuthentication}
impl Rig {
    async fn new()->Self {
        let dsn=std::env::var("TEST_DATABASE_URL").expect("use scripts/test-postgres.sh with a disposable PostgreSQL 16 database");
        assert_eq!(url::Url::parse(&dsn).unwrap().path(),"/bz_foundation_test","refusing non-test database name");
        let pool=PgPoolOptions::new().max_connections(16).connect(&dsn).await.unwrap();
        let version:String=sqlx::query_scalar("SHOW server_version_num").fetch_one(&pool).await.unwrap();
        assert!((160000..170000).contains(&version.parse::<u32>().unwrap()),"selected PostgreSQL 16 required");
        let key=nostr::Keys::generate();
        // Disposable random signing key; no checked-in or real private credential.
        let signing=loop {let mut bytes=[0u8;32];bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());if let Ok(k)=SigningKey::from_slice(&bytes){break k;}};
        let pem=signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer=jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let public=signing.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
        let actions:BTreeSet<String>=["enroll","prove-key","change-access","retire-key","start-task","observe-task","claim-worker","renew-worker","cancel-task","reconcile-task","complete-task","set-label","publish","reconcile-effect","reserve-model-budget"].into_iter().map(str::to_owned).collect();
        let module=ModulePolicy{actions,principal_issuers:BTreeSet::from(["https://identity.synthetic.invalid".into()]),context_domains:BTreeSet::from(["synthetic-domain".into()]),task_schemas:BTreeSet::from(["synthetic-task-v1".into()]),tools:BTreeMap::from([(SetLabel::SCHEMA_ID.into(),ToolPolicy{action:SetLabel::ACTION.into(),schema_sha256:digest(&SetLabel::schema()).unwrap(),effect_owner:"synthetic-owner".into(),requires_verdict:false})])};
        let registration=Registration{consumer_id:format!("synthetic-{}",Uuid::new_v4()),revision:1,policy_revision:"policy-1".into(),authority_epoch:1,community_id:"synthetic-community".into(),service_principal:"synthetic-service".into(),service_public_key:key.public_key().to_hex(),issuer:"https://consumer.synthetic.invalid".into(),audiences:[INVOCATION,PUBLICATION,EVIDENCE].into_iter().map(|p|(p.into(),"https://provider.synthetic.invalid".into())).collect(),verification_keys:BTreeMap::from([("disposable-key".into(),public)]),enrollment_bot_key:nostr::Keys::generate().public_key().to_hex(),enrollment_channel:"synthetic-enrollment".into(),modules:BTreeMap::from([("module-a".into(),module.clone()),("module-b".into(),module)]),retention:Retention{task_days:1,publication_days:1,audit_days:1},pricing:Some(Pricing{revision:"synthetic-not-a-vendor-quote".into(),model_profile:"sonnet-5-adaptive-bounded-v1".into(),checked_at:Utc::now()-CD::seconds(1),valid_until:Utc::now()+CD::hours(1),input_usd_micros_per_million:2_000_000,output_usd_micros_per_million:10_000_000})};
        let p=Provider::new(pool.clone(),"https://provider.synthetic.invalid",1).unwrap();p.migrate().await.unwrap();p.register(registration.clone(),None).await.unwrap();
        let browser=BrowserAuthentication{issuer:"https://identity.synthetic.invalid".into(),subject:"synthetic-person".into(),transaction_id:Uuid::new_v4().to_string(),authenticated_at:Utc::now().timestamp(),expires_at:(Utc::now()+CD::minutes(5)).timestamp()};
        Self{p,pool,registration,key,signer,browser}
    }
    fn resource(&self,name:&str,revision:u64)->Resource {Resource{namespace:self.registration.consumer_id.clone(),reference:name.into(),revision:revision.to_string()}}
    fn command<T:Serialize>(&self,op:&str,resource:Resource,payload:T)->Command {Command{contract:CONTRACT.into(),profile:PROFILE.into(),consumer_id:self.registration.consumer_id.clone(),intent_id:Uuid::new_v4().to_string(),operation:op.into(),resource,correlation_id:"synthetic-correlation".into(),causation_id:"synthetic-cause".into(),payload:serde_json::to_value(payload).unwrap()}}
    fn claims(&self,c:&Command,module:&str,root:Option<&str>,binding:Option<&Binding>)->Claims {
        let now=Utc::now().timestamp();
        Claims{iss:self.registration.issuer.clone(),aud:self.registration.audiences[INVOCATION].clone(),sub:self.registration.service_principal.clone(),consumer_id:c.consumer_id.clone(),intent_id:c.intent_id.clone(),operation:c.operation.clone(),resource:c.resource.clone(),resource_revision:c.resource.revision.clone(),payload_sha256:c.fingerprint().unwrap(),policy_revision:self.registration.policy_revision.clone(),authority_epoch:binding.map(|b|b.authority_epoch as u64).unwrap_or(1),recovery_epoch:1,iat:now,exp:now+60,jti:Uuid::new_v4().to_string(),module_id:module.into(),context_domain:"synthetic-domain".into(),authority_checked_at:now,registration_revision:1,enrollment_id:binding.map(|b|b.enrollment_id.clone()),enrollment_revision:binding.map(|b|b.revision as u64),represented_principal:binding.map(|b|b.subject.clone()),delegation_id:binding.map(|_|"synthetic-delegation".into()),root_task_id:root.map(str::to_owned),grant_revision:binding.map(|_|"1".into()),browser_authentication:None,verdicts:vec![],release:None}
    }
    fn sign(&self,path:&str,method:&str,body:&[u8],claims:&Claims,purpose:&str)->Signed {
        let mut header=jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);header.typ=Some(purpose.into());header.kid=Some("disposable-key".into());
        let assertion=jsonwebtoken::encode(&header,claims,&self.signer).unwrap();
        let url=format!("https://provider.synthetic.invalid{path}");let payload=sha256(body);let nonce=Uuid::new_v4().to_string();
        let tags=vec![nostr::Tag::parse(["u",url.as_str()]).unwrap(),nostr::Tag::parse(["method",method]).unwrap(),nostr::Tag::parse(["payload",payload.as_str()]).unwrap(),nostr::Tag::parse(["nonce",nonce.as_str()]).unwrap()];
        let event=nostr::EventBuilder::new(nostr::Kind::HttpAuth,"").tags(tags).sign_with_keys(&self.key).unwrap();
        Signed{resource:format!("Nostr {}",STANDARD.encode(serde_json::to_vec(&event).unwrap())),assertion}
    }
    fn prepare(&self,path:&str,c:&Command,claims:&Claims)->(Vec<u8>,Signed) {let b=canonical(c).unwrap();let h=self.sign(path,"POST",&b,claims,INVOCATION);(b,h)}
    async fn enroll(&self,module:&str,key:&nostr::Keys)->(Binding,Command,Vec<u8>) {
        let e=Enroll{issuer:self.browser.issuer.clone(),subject:self.browser.subject.clone(),intended_public_key:key.public_key().to_hex(),community_id:self.registration.community_id.clone(),module_id:module.into(),browser_transaction_id:self.browser.transaction_id.clone()};
        let c=self.command("enroll",self.resource("principal",1),e);let mut claims=self.claims(&c,module,None,None);claims.browser_authentication=Some(self.browser.clone());
        let (body,h)=self.prepare("/integration/v1/enrollments",&c,&claims);
        let challenge:EnrollmentChallenge=serde_json::from_value(self.p.enroll(&body,h.headers()).await.unwrap().result).unwrap();
        // Reusing the exact resource auth/JTI fails before any second consumption.
        assert!(self.p.enroll(&body,h.headers()).await.is_err());
        let make_event=|key:&nostr::Keys|nostr::EventBuilder::new(nostr::Kind::from(buzz_core::kind::KIND_STREAM_MESSAGE as u16),challenge.message_text.clone()).tags([nostr::Tag::parse(["p",challenge.bot_public_key.as_str()]).unwrap(),nostr::Tag::parse(["h",challenge.channel_id.as_str()]).unwrap()]).sign_with_keys(key).unwrap();
        let path=format!("/integration/v1/enrollments/{}/proof",challenge.enrollment_id);
        let wrong=self.command("prove-key",self.resource(&challenge.enrollment_id,1),ProveKey{enrollment_id:challenge.enrollment_id.clone(),native_event:serde_json::to_value(make_event(&nostr::Keys::generate())).unwrap()});
        let mut claim=self.claims(&wrong,module,None,None);claim.browser_authentication=Some(self.browser.clone());let (bad,h)=self.prepare(&path,&wrong,&claim);assert!(self.p.prove_key(&challenge.enrollment_id,&bad,h.headers()).await.is_err());
        let c=self.command("prove-key",self.resource(&challenge.enrollment_id,1),ProveKey{enrollment_id:challenge.enrollment_id.clone(),native_event:serde_json::to_value(make_event(key)).unwrap()});
        let mut claim=self.claims(&c,module,None,None);claim.browser_authentication=Some(self.browser.clone());let (body,h)=self.prepare(&path,&c,&claim);
        let result=self.p.prove_key(&challenge.enrollment_id,&body,h.headers()).await.unwrap();let binding=serde_json::from_value(result.result).unwrap();
        let mut replay=c.clone();replay.intent_id=Uuid::new_v4().to_string();let mut claim=self.claims(&replay,module,None,None);claim.browser_authentication=Some(self.browser.clone());let (replay,h)=self.prepare(&path,&replay,&claim);assert!(self.p.prove_key(&challenge.enrollment_id,&replay,h.headers()).await.is_err());
        (binding,c,body)
    }
    async fn start(&self,binding:Option<&Binding>,module:&str,lifetime:i64)->TaskManifest {
        let root=Uuid::new_v4().to_string();
        let manifest=TaskManifest{task_id:root.clone(),root_task_id:root.clone(),task_schema_id:"synthetic-task-v1".into(),context_domain:"synthetic-domain".into(),model_profile:"sonnet-5-adaptive-bounded-v1".into(),expires_at:Utc::now()+CD::seconds(lifetime),tools:vec![Tool{schema_id:SetLabel::SCHEMA_ID.into(),schema_sha256:digest(&SetLabel::schema()).unwrap(),action:SetLabel::ACTION.into(),resources:vec![self.resource(&format!("record-{module}"),1),self.resource(&format!("record-{module}-alt"),1)]}],budgets:Budgets{model_attempts:8,tool_admissions:32,input_tokens_per_generation:32_000,input_tokens_total:128_000,output_tokens_total:16_000,usd_micros:1_000_000,automatic_restarts:3},verdict_refs:vec![]};
        let c=self.command("start-task",manifest.tools[0].resources[0].clone(),&manifest);let claims=self.claims(&c,module,Some(&root),binding);let (body,h)=self.prepare("/integration/v1/tasks",&c,&claims);self.p.start_task(&body,h.headers()).await.unwrap();manifest
    }
    async fn worker(&self,task:&TaskManifest,binding:Option<&Binding>,module:&str,generation:u64,renew:bool)->Worker {
        let c=self.command(if renew{"renew-worker"}else{"claim-worker"},self.resource(&task.task_id,generation),WorkerRequest{task_id:task.task_id.clone(),expected_generation:generation,worker_id:"synthetic-worker".into()});
        let path=format!("/integration/foundation/v1/tasks/{}/{}",task.task_id,if renew{"renew"}else{"claim"});let claims=self.claims(&c,module,Some(&task.root_task_id),binding);let(body,h)=self.prepare(&path,&c,&claims);
        serde_json::from_value(self.p.worker_control(&task.task_id,renew,&body,h.headers()).await.unwrap().result).unwrap()
    }
    fn tool(&self,task:&TaskManifest,generation:u64)->ToolCall<SetLabel> {ToolCall{consumer_id:self.registration.consumer_id.clone(),intent_id:Uuid::new_v4().to_string(),root_task_id:task.root_task_id.clone(),task_id:task.task_id.clone(),generation,effect_owner:"synthetic-owner".into(),effect_intent_id:Uuid::new_v4().to_string(),schema_id:SetLabel::SCHEMA_ID.into(),schema_sha256:digest(&SetLabel::schema()).unwrap(),action:SetLabel::ACTION.into(),resource:task.tools[0].resources[0].clone(),arguments:SetLabel{label:"Synthetic ready".into()}}}
    fn tool_request(&self,c:&ToolCall<SetLabel>,binding:Option<&Binding>,module:&str)->(Vec<u8>,Claims) {
        let mut envelope=self.command(&c.action,c.resource.clone(),&c.arguments);envelope.intent_id=c.intent_id.clone();
        let mut claims=self.claims(&envelope,module,Some(&c.root_task_id),binding);claims.payload_sha256=digest(c).unwrap();(canonical(c).unwrap(),claims)
    }
    async fn admit(&self,c:&ToolCall<SetLabel>,binding:Option<&Binding>,module:&str)->llull_buzz_provider::Result<ToolAdmission<SetLabel>> {
        let(body,claims)=self.tool_request(c,binding,module);let h=self.sign(&format!("/integration/foundation/v1/tool-admissions/{}",SetLabel::SCHEMA_ID),"POST",&body,&claims,INVOCATION);
        self.p.admit_tool("synthetic-worker",&body,h.headers()).await
    }
    async fn cancel(&self,task:&TaskManifest,binding:Option<&Binding>,module:&str,generation:u64)->CommandResult {
        let c=self.command("cancel-task",self.resource(&task.task_id,generation),TaskControl{task_id:task.task_id.clone(),expected_generation:generation,reason:"synthetic test cleanup".into()});let claims=self.claims(&c,module,Some(&task.root_task_id),binding);let(body,h)=self.prepare(&format!("/integration/v1/tasks/{}/cancel",task.task_id),&c,&claims);self.p.control_task(&task.task_id,false,&body,h.headers()).await.unwrap()
    }
}
#[derive(Default)] struct Consumer {calls:AtomicUsize,lookups:AtomicUsize,lost:bool,records:Mutex<BTreeMap<String,ConsumerResult>>}
#[async_trait] impl ConsumerPort<SetLabel> for Consumer {
    fn owner(&self)->&str {"synthetic-owner"}
    async fn execute(&self,c:&ToolCall<SetLabel>,bytes:&[u8],_:&str,_:Duration)->std::result::Result<ConsumerResult,PortError> {
        self.calls.fetch_add(1,Ordering::SeqCst);
        let result=ConsumerResult{owner:self.owner().into(),effect_intent_id:c.effect_intent_id.clone(),request_sha256:sha256(bytes),status:ConsumerStatus::Completed,result_ref:Some(format!("synthetic-result-{}",c.effect_intent_id))};
        assert!(self.records.lock().unwrap().insert(c.effect_intent_id.clone(),result.clone()).is_none(),"consumer effect was executed twice");
        if self.lost {Err(PortError)}else{Ok(result)}
    }
    async fn lookup(&self,body:&[u8],_:&str,_:Duration)->std::result::Result<ConsumerResult,PortError> {
        self.lookups.fetch_add(1,Ordering::SeqCst);let c:Command=parse(body).unwrap();let request:RecoverEffect=c.payload().unwrap();
        self.records.lock().unwrap().get(&request.effect_intent_id).cloned().ok_or(PortError)
    }
}
fn permit(admission:ToolAdmission<SetLabel>)->DispatchPermit<SetLabel> {match admission{ToolAdmission::Dispatch(p)=>p,_=>panic!("expected one new durable reservation")}}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16; scripts/test-postgres.sh"]
async fn postgres_foundation_contracts() {
    let rig=Rig::new().await;let native=nostr::Keys::generate();
    let (binding,_,_)=rig.enroll("module-a",&native).await;
    let (other,_,_)=rig.enroll("module-b",&native).await;
    let task=rig.start(Some(&binding),"module-a",600).await;rig.worker(&task,Some(&binding),"module-a",1,false).await;
    let call=rig.tool(&task,1);
    // Exact signed authorized completion; a real database owns the reservation.
    let consumer=Consumer::default();let admitted=rig.admit(&call,Some(&binding),"module-a").await.unwrap();
    let attempt=rig.p.dispatch(permit(admitted),&consumer).await.unwrap();assert_eq!(attempt.state,"completed");assert_eq!(consumer.calls.load(Ordering::SeqCst),1);
    assert!(matches!(rig.admit(&call,Some(&binding),"module-a").await.unwrap(),ToolAdmission::Existing(_)));
    let mut changed=call.clone();changed.arguments.label="Changed intent".into();assert!(rig.admit(&changed,Some(&binding),"module-a").await.is_err());
    // Forged signature, scope, action or purpose cannot authorize an admitted type.
    let (body,mut claims)=rig.tool_request(&rig.tool(&task,1),Some(&binding),"module-a");claims.context_domain="forged-domain".into();
    let path=format!("/integration/foundation/v1/tool-admissions/{}",SetLabel::SCHEMA_ID);let h=rig.sign(&path,"POST",&body,&claims,INVOCATION);assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let (body,claims)=rig.tool_request(&rig.tool(&task,1),Some(&binding),"module-a");let mut h=rig.sign(&path,"POST",&body,&claims,INVOCATION);h.assertion.push('x');assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let h=rig.sign(&path,"POST",&body,&claims,PUBLICATION);assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let mut h=rig.sign(&path,"POST",&body,&claims,INVOCATION);h.resource="Nostr invalid".into();assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let h=rig.sign(&path,"POST",b"changed raw body",&claims,INVOCATION);assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let url=format!("https://provider.synthetic.invalid{path}");
    let no_hash=nostr::EventBuilder::new(nostr::Kind::HttpAuth,"").tags([nostr::Tag::parse(["u",url.as_str()]).unwrap(),nostr::Tag::parse(["method","POST"]).unwrap()]).sign_with_keys(&rig.key).unwrap();
    let mut h=rig.sign(&path,"POST",&body,&claims,INVOCATION);h.resource=format!("Nostr {}",STANDARD.encode(serde_json::to_vec(&no_hash).unwrap()));assert!(rig.p.admit_tool::<SetLabel>("synthetic-worker",&body,h.headers()).await.is_err());
    let completion=rig.command("complete-task",rig.resource(&task.task_id,1),CompleteTask{task_id:task.task_id.clone(),expected_generation:1,completed_effects:vec![CompletedEffect{attempt_id:attempt.attempt_id,effect_owner:attempt.effect_owner.clone(),effect_intent:attempt.effect_intent_id.clone(),request_sha256:attempt.request_sha256.clone(),result_ref:attempt.result_ref.clone().unwrap()}]});
    let claims=rig.claims(&completion,"module-a",Some(&task.root_task_id),Some(&binding));let(body,h)=rig.prepare(&format!("/integration/foundation/v1/tasks/{}/complete",task.task_id),&completion,&claims);assert_eq!(rig.p.complete_task(&task.task_id,&body,h.headers()).await.unwrap().receipt.execution,Execution::Completed);

    // Consumer committed, but the response was lost: new IDs cannot repeat it.
    let uncertain=rig.start(Some(&binding),"module-a",600).await;rig.worker(&uncertain,Some(&binding),"module-a",1,false).await;
    let call=rig.tool(&uncertain,1);let consumer=Consumer{lost:true,..Consumer::default()};
    let attempt=rig.p.dispatch(permit(rig.admit(&call,Some(&binding),"module-a").await.unwrap()),&consumer).await.unwrap();assert_eq!(attempt.state,"effect-unknown");
    assert!(rig.admit(&rig.tool(&uncertain,1),Some(&binding),"module-a").await.is_err());
    let alias=rig.start(Some(&binding),"module-a",600).await;rig.worker(&alias,Some(&binding),"module-a",1,false).await;
    assert!(rig.admit(&rig.tool(&alias,1),Some(&binding),"module-a").await.is_err(),"a new authorized root cannot rename an uncertain existing effect");
    rig.cancel(&alias,Some(&binding),"module-a",1).await;
    let recovery=rig.command("reconcile-effect",call.resource.clone(),RecoverEffect{task_id:call.task_id.clone(),expected_generation:1,attempt_id:attempt.attempt_id,effect_owner:attempt.effect_owner.clone(),effect_intent_id:attempt.effect_intent_id.clone(),request_sha256:attempt.request_sha256.clone()});
    let claims=rig.claims(&recovery,"module-a",Some(&call.root_task_id),Some(&binding));let(body,h)=rig.prepare(&format!("/integration/foundation/v1/effects/{}/reconcile/{}",attempt.attempt_id,SetLabel::SCHEMA_ID),&recovery,&claims);
    assert_eq!(rig.p.recover_effect::<SetLabel,_>(attempt.attempt_id,&body,h.headers(),&consumer).await.unwrap().state,"completed");assert_eq!(consumer.calls.load(Ordering::SeqCst),1);assert_eq!(consumer.lookups.load(Ordering::SeqCst),1);
    assert_eq!(rig.cancel(&uncertain,Some(&binding),"module-a",1).await.receipt.execution,Execution::Pending,"partial completed effects are not canceled-before-effect");

    // Revocation fences an existing dispatch permit, preserves another module and history.
    let revoke_task=rig.start(Some(&binding),"module-a",600).await;rig.worker(&revoke_task,Some(&binding),"module-a",1,false).await;
    let admitted=permit(rig.admit(&rig.tool(&revoke_task,1),Some(&binding),"module-a").await.unwrap());
    let revoke=rig.command("change-access",rig.resource(&binding.enrollment_id,1),ChangeAccess{enrollment_id:binding.enrollment_id.clone(),expected_revision:"1".into(),change:AccessChange::Revoke});let claims=rig.claims(&revoke,"module-a",None,None);let(body,h)=rig.prepare("/integration/v1/access-changes",&revoke,&claims);rig.p.change_access(&body,h.headers()).await.unwrap();
    assert!(rig.p.dispatch(admitted,&Consumer::default()).await.is_err());
    let unaffected:(bool,i64)=sqlx::query_as("SELECT active,revision FROM enrollments WHERE enrollment_id=$1").bind(&other.enrollment_id).fetch_one(&rig.pool).await.unwrap();assert_eq!(unaffected,(true,1));
    let history:i64=sqlx::query_scalar("SELECT count(*) FROM enrollment_history WHERE enrollment_id=$1").bind(&binding.enrollment_id).fetch_one(&rig.pool).await.unwrap();assert_eq!(history,2);
    assert!(sqlx::query("DELETE FROM enrollment_history WHERE enrollment_id=$1").bind(&binding.enrollment_id).execute(&rig.pool).await.is_err());

    // Children and simultaneous admissions share one real row-locked budget.
    let budget=rig.start(Some(&other),"module-b",600).await;rig.worker(&budget,Some(&other),"module-b",1,false).await;
    let mut child=budget.clone();child.task_id=Uuid::new_v4().to_string();let c=rig.command("start-task",rig.resource("record-a",1),&child);let claims=rig.claims(&c,"module-b",Some(&child.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/v1/tasks",&c,&claims);rig.p.start_task(&body,h.headers()).await.unwrap();
    let mut widened=child.clone();widened.task_id=Uuid::new_v4().to_string();widened.expires_at+=CD::seconds(1);
    let c=rig.command("start-task",rig.resource("record-a",1),&widened);let claims=rig.claims(&c,"module-b",Some(&widened.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/v1/tasks",&c,&claims);assert!(rig.p.start_task(&body,h.headers()).await.is_err());
    for index in 0..4 {
        let member=if index%2==0{&budget}else{&child};
        let reservation=llull_buzz_provider::budget::ModelReservation{task_id:member.task_id.clone(),expected_generation:1,worker_id:"synthetic-worker".into(),pricing_revision:"synthetic-not-a-vendor-quote".into(),prompt_sha256:sha256(format!("synthetic-prompt-{index}").as_bytes()),input_upper_bound:32_000,output_upper_bound:4_000};
        let c=rig.command("reserve-model-budget",rig.resource(&member.task_id,1),&reservation);let claims=rig.claims(&c,"module-b",Some(&member.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/foundation/v1/model-reservations",&c,&claims);
        let result=rig.p.reserve_model_budget(&body,h.headers()).await.unwrap();assert_eq!(result.result["model_dispatch"],"unavailable");
    }
    let reservation=llull_buzz_provider::budget::ModelReservation{task_id:child.task_id.clone(),expected_generation:1,worker_id:"synthetic-worker".into(),pricing_revision:"synthetic-not-a-vendor-quote".into(),prompt_sha256:sha256(b"over-budget"),input_upper_bound:1,output_upper_bound:1};
    let c=rig.command("reserve-model-budget",rig.resource(&child.task_id,1),&reservation);let claims=rig.claims(&c,"module-b",Some(&child.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/foundation/v1/model-reservations",&c,&claims);assert!(rig.p.reserve_model_budget(&body,h.headers()).await.is_err());
    // Complete each effect before the next same-slot mutation. Child work still spends root counters.
    let consumer=Consumer::default();
    for index in 0..31 {if index%5==0 {rig.worker(&budget,Some(&other),"module-b",1,true).await;}let member=if index%2==0{&budget}else{&child};let c=rig.tool(member,1);let attempt=rig.p.dispatch(permit(rig.admit(&c,Some(&other),"module-b").await.unwrap()),&consumer).await.unwrap();assert_eq!(attempt.state,"completed");}
    let a=rig.tool(&budget,1);let mut b=rig.tool(&child,1);b.resource=child.tools[0].resources[1].clone();
    let (left,right)=tokio::join!(rig.admit(&a,Some(&other),"module-b"),rig.admit(&b,Some(&other),"module-b"));
    assert_eq!(usize::from(left.is_ok())+usize::from(right.is_ok()),1);
    let admitted=left.or(right).unwrap();rig.p.dispatch(permit(admitted),&consumer).await.unwrap();
    assert!(rig.admit(&rig.tool(&child,1),Some(&other),"module-b").await.is_err());
    let state:sqlx::types::Json<TaskState>=sqlx::query_scalar("SELECT state FROM task_roots WHERE consumer_id=$1 AND root_task_id=$2").bind(&rig.registration.consumer_id).bind(&budget.root_task_id).fetch_one(&rig.pool).await.unwrap();assert_eq!(state.0.spent.tool_admissions,32);assert_eq!(state.0.spent.input_tokens,128_000);assert_eq!(state.0.spent.output_tokens,16_000);assert_eq!(state.0.spent.model_attempts,4);
    // Real lease time passes; process replacement cannot replenish budget or expiry.
    tokio::time::sleep(Duration::from_secs(31)).await;
    let worker=rig.worker(&budget,Some(&other),"module-b",1,false).await;assert_eq!(worker.generation,2);
    assert!(rig.admit(&rig.tool(&budget,1),Some(&other),"module-b").await.is_err());assert!(rig.admit(&rig.tool(&budget,2),Some(&other),"module-b").await.is_err());
    rig.cancel(&budget,Some(&other),"module-b",2).await;
    let expired=rig.start(Some(&other),"module-b",2).await;rig.worker(&expired,Some(&other),"module-b",1,false).await;tokio::time::sleep(Duration::from_secs(3)).await;assert!(rig.admit(&rig.tool(&expired,1),Some(&other),"module-b").await.is_err());

    // Real concurrent root admission: exactly four, not four per worker/consumer.
    let mut candidates=Vec::new();
    for _ in 0..6 {let mut m=expired.clone();m.task_id=Uuid::new_v4().to_string();m.root_task_id=m.task_id.clone();m.expires_at=Utc::now()+CD::seconds(600);candidates.push(m);}
    let futures=candidates.iter().map(|m|async {
        let c=rig.command("start-task",rig.resource("record-a",1),m);let claims=rig.claims(&c,"module-b",Some(&m.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/v1/tasks",&c,&claims);rig.p.start_task(&body,h.headers()).await
    });
    let admitted=futures_util::future::join_all(futures).await;assert_eq!(admitted.iter().filter(|r|r.is_ok()).count(),4);
    for (m,result) in candidates.iter().zip(admitted) {if result.is_ok(){rig.cancel(m,Some(&other),"module-b",1).await;}}

    // Publication admission cannot substitute text, audience or release identity.
    let publication=Publication{community_id:rig.registration.community_id.clone(),channel_id:"synthetic-destination".into(),audience_policy:"synthetic-audience".into(),audience_revision:"1".into(),release_ref:Uuid::new_v4().to_string(),text:"Synthetic public text".into(),text_sha256:sha256(b"Synthetic public text"),copy_mode:CopyMode::SummaryLink,attachments:vec![]};
    let c=rig.command("publish",rig.resource("publication",1),&publication);let mut claims=rig.claims(&c,"module-b",None,None);claims.release=Some(Release{release_ref:publication.release_ref.clone(),community_id:publication.community_id.clone(),channel_id:publication.channel_id.clone(),audience_policy:publication.audience_policy.clone(),audience_revision:"1".into(),publication_sha256:digest(&publication).unwrap(),checked_at:Utc::now().timestamp()});
    let body=canonical(&c).unwrap();let h=rig.sign("/integration/v1/publications","POST",&body,&claims,PUBLICATION);let accepted=rig.p.admit_publication(&body,h.headers()).await.unwrap();assert_eq!(accepted.receipt.execution,Execution::Pending);assert_eq!(accepted.result["delivery"],"unavailable");
    let mut altered=c.clone();altered.intent_id=Uuid::new_v4().to_string();altered.payload["channel_id"]=json!("other-audience");let mut forged=claims.clone();forged.intent_id=altered.intent_id.clone();forged.jti=Uuid::new_v4().to_string();forged.payload_sha256=altered.fingerprint().unwrap();let body=canonical(&altered).unwrap();let h=rig.sign("/integration/v1/publications","POST",&body,&forged,PUBLICATION);assert!(rig.p.admit_publication(&body,h.headers()).await.is_err());
    let mut altered=c.clone();altered.intent_id=Uuid::new_v4().to_string();let mut reused=claims.clone();reused.intent_id=altered.intent_id.clone();reused.jti=Uuid::new_v4().to_string();reused.payload_sha256=altered.fingerprint().unwrap();let body=canonical(&altered).unwrap();let h=rig.sign("/integration/v1/publications","POST",&body,&reused,PUBLICATION);assert!(rig.p.admit_publication(&body,h.headers()).await.is_err());

    let mut altered=c.clone();altered.intent_id=Uuid::new_v4().to_string();altered.payload["text"]=json!("different exact text");altered.payload["text_sha256"]=json!(sha256(b"different exact text"));
    let mut substituted=claims.clone();substituted.intent_id=altered.intent_id.clone();substituted.jti=Uuid::new_v4().to_string();substituted.payload_sha256=altered.fingerprint().unwrap();let body=canonical(&altered).unwrap();let h=rig.sign("/integration/v1/publications","POST",&body,&substituted,PUBLICATION);assert!(rig.p.admit_publication(&body,h.headers()).await.is_err());

    // Outside-held recovery epoch prevents a restored old admission namespace.
    let restored=Provider::new(rig.pool.clone(),"https://provider.synthetic.invalid",2).unwrap();
    assert!(restored.admit_publication(&body,h.headers()).await.is_err());assert_eq!(restored.advance_recovery_epoch(1).await.unwrap(),2);
    let c=rig.command("start-task",rig.resource("record-a",1),&expired);let claims=rig.claims(&c,"module-b",Some(&expired.root_task_id),Some(&other));let(body,h)=rig.prepare("/integration/v1/tasks",&c,&claims);assert!(rig.p.start_task(&body,h.headers()).await.is_err());
}
