//! Credential-free launch/configuration boundary, not an agent harness or OS
//! sandbox. Actual containment and native compatibility require the local probes.
#![forbid(unsafe_code)]
use llull_buzz_wire::{canonical,hash,parse,sha256,Fault,Result};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use std::{collections::BTreeMap,path::{Path,PathBuf},process::Stdio};

pub const AGENT:&str="/opt/llull/upstream/buzz-agent";
pub const ACP:&str="/opt/llull/upstream/buzz-acp";
pub const BRIDGE:&str="/opt/llull/bin/llull-buzz-mcp-probe";
pub const WORK:&str="/work/task";
pub const HOME:&str="/work/task/home";
pub const TMP:&str="/work/task/tmp";
#[derive(Debug,Clone,Copy)] pub enum Program {Agent,AcpHelp,McpProbe}
impl Program {
    pub fn path(self)->&'static str {match self {Self::Agent=>AGENT,Self::AcpHelp=>ACP,Self::McpProbe=>BRIDGE}}
    pub fn arguments(self)->&'static [&'static str] {match self {Self::AcpHelp=>&["--help"],_=>&[]}}
}
/// These values are fixed in source; no inherited key, path, proxy, shell, loader,
/// credential directory or wire declaration participates. The dummy string is NOT
/// a provider credential. Model requests cannot pass the ACP guard in this slice.
pub fn environment()->BTreeMap<&'static str,&'static str> {
    BTreeMap::from([
        ("PATH","/nonexistent"),("HOME",HOME),("TMPDIR",TMP),("LANG","C.UTF-8"),
        ("ANTHROPIC_API_KEY","foundation-probe-not-a-provider-key"),
        ("ANTHROPIC_BASE_URL","http://127.0.0.1:9"),
        ("BUZZ_AGENT_MAX_SESSIONS","1"),("BUZZ_AGENT_MAX_ROUNDS","1"),
        ("BUZZ_AGENT_MAX_OUTPUT_TOKENS","1"),("BUZZ_AGENT_MAX_CONTEXT_TOKENS","32000"),
        ("BUZZ_AGENT_MAX_LINE_BYTES","1048576"),("BUZZ_AGENT_MAX_HISTORY_BYTES","16777216"),
        ("BUZZ_AGENT_MAX_PARALLEL_TOOLS","1"),("BUZZ_AGENT_MAX_HANDOFFS","0"),
        ("BUZZ_AGENT_LLM_TIMEOUT_SECS","1"),("BUZZ_AGENT_TOOL_TIMEOUT_SECS","5"),
        ("BUZZ_AGENT_MCP_INIT_TIMEOUT_SECS","5"),("BUZZ_AGENT_MCP_RESTART_MAX_ATTEMPTS","1"),
        ("BUZZ_AGENT_NO_HINTS","1"),("BUZZ_AGENT_PROMPT_CACHING","0"),
    ])
}
fn fixed_command(program:Program)->tokio::process::Command {
    let mut command=tokio::process::Command::new(program.path());
    command.args(program.arguments()).current_dir(WORK).env_clear().envs(environment())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    command
}
#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {pub upstream_commit:String,pub executable_sha256:BTreeMap<String,String>}
impl ImageIdentity {
    pub fn load()->Result<Self> {
        let path=Path::new("/opt/llull/identities.json");
        immutable_file(path,false)?;
        parse(&std::fs::read(path).map_err(|_|Fault::Unavailable)?)
    }
    pub fn verify(&self)->Result<()> {
        #[cfg(target_os="linux")]
        {
            let status=std::fs::read_to_string("/proc/self/status").map_err(|_|Fault::Unavailable)?;
            let effective=status.lines().find(|line|line.starts_with("Uid:"))
                .and_then(|line|line.split_whitespace().nth(2));
            if effective!=Some("65532") {return Err(Fault::Denied);}
        }
        #[cfg(not(target_os="linux"))] {return Err(Fault::Unavailable);}

        if self.upstream_commit!=llull_buzz_wire::UPSTREAM || self.executable_sha256.len()!=3 {return Err(Fault::Denied);}
        for program in [Program::Agent,Program::AcpHelp,Program::McpProbe] {
            let path=Path::new(program.path());
            immutable_file(path,true)?;
            let expected=self.executable_sha256.get(program.path()).ok_or(Fault::Denied)?;hash(expected)?;
            let bytes=std::fs::read(path).map_err(|_|Fault::Unavailable)?;
            if sha256(&bytes)!=*expected {return Err(Fault::Denied);}
        }
        for directory in [WORK,HOME,TMP] {
            let path=Path::new(directory);
            if std::fs::canonicalize(path).map_err(|_|Fault::Unavailable)?!=path || !path.is_dir() {return Err(Fault::Denied);}
        }
        Ok(())
    }
}
/// Hash and image-ownership checks are mandatory before obtaining a launch command.
pub fn checked_command(identity:&ImageIdentity,program:Program)->Result<tokio::process::Command> {
    identity.verify()?;Ok(fixed_command(program))
}

#[cfg(unix)] fn immutable_file(path:&Path,executable:bool)->Result<()> {
    use std::os::unix::fs::MetadataExt;
    if std::fs::canonicalize(path).map_err(|_|Fault::Unavailable)?!=path {return Err(Fault::Denied);}
    for component in path.ancestors() {
        let metadata=std::fs::symlink_metadata(component).map_err(|_|Fault::Unavailable)?;
        if metadata.file_type().is_symlink() || metadata.uid()!=0 || metadata.mode()&0o022!=0 {return Err(Fault::Denied);}
    }
    let metadata=std::fs::metadata(path).map_err(|_|Fault::Unavailable)?;
    if !metadata.is_file() || (executable && metadata.mode()&0o111==0) {return Err(Fault::Denied);}
    Ok(())
}
#[cfg(not(unix))] fn immutable_file(_path:&Path,_executable:bool)->Result<()> {Err(Fault::Unavailable)}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)] pub struct EnvVar {pub name:String,pub value:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)] pub struct McpServer {pub name:String,pub command:String,pub args:Vec<String>,pub env:Vec<EnvVar>}
pub fn admitted_mcp()->McpServer {McpServer{name:"llull-foundation-probe".into(),command:BRIDGE.into(),args:vec![],env:vec![]}}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)] struct Frame {jsonrpc:String,id:Value,method:String,params:Value}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")] struct SessionNew {cwd:PathBuf,mcp_servers:Vec<McpServer>}
#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")] struct SessionCancel {session_id:String}
#[derive(Default)] pub struct AcpGuard {initialized:bool,created:bool,session:Option<String>}
impl AcpGuard {
    pub fn admit(&mut self,bytes:&[u8])->Result<Vec<u8>> {
        let frame:Frame=parse(bytes)?;
        if frame.jsonrpc!="2.0" || !(frame.id.is_string() || frame.id.is_u64()) {return Err(Fault::Invalid);}
        let params=match frame.method.as_str() {
            "initialize"=>{
                if self.initialized || frame.params!=json!({"protocolVersion":2,"clientCapabilities":{},"clientInfo":{"name":"llull-foundation-probe","version":"0.1.0"}}) {return Err(Fault::Denied);}
                self.initialized=true;frame.params
            }
            "session/new"=>{
                if !self.initialized || self.created {return Err(Fault::Denied);}
                let requested:SessionNew=serde_json::from_value(frame.params).map_err(|_|Fault::Invalid)?;
                if requested.cwd!=Path::new(WORK) || requested.mcp_servers!=vec![admitted_mcp()] {return Err(Fault::Denied);}
                self.created=true;json!({"cwd":WORK,"mcpServers":[admitted_mcp()]})
            }
            "session/cancel"=>{
                let requested:SessionCancel=serde_json::from_value(frame.params).map_err(|_|Fault::Invalid)?;
                if self.session.as_deref()!=Some(requested.session_id.as_str()) {return Err(Fault::Denied);}
                json!({"sessionId":requested.session_id})
            }
            // No prompts, steer, set_model, arbitrary child commands, hooks,
            // permission responses, MCP tools/call or opaque extension forwarding.
            _=>return Err(Fault::Unavailable),
        };
        canonical(&json!({"jsonrpc":"2.0","id":frame.id,"method":frame.method,"params":params}))
    }
    pub fn record_session(&mut self,session_id:&str)->Result<()> {
        llull_buzz_wire::id(session_id)?;
        if !self.created || self.session.is_some() {return Err(Fault::Conflict);}
        self.session=Some(session_id.into());Ok(())
    }
}

#[cfg(test)] mod tests {
    use super::*;
    fn frame(method:&str,params:Value)->Vec<u8> {canonical(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).unwrap()}
    fn initialized()->AcpGuard {
        let mut guard=AcpGuard::default();guard.admit(&frame("initialize",json!({"protocolVersion":2,"clientCapabilities":{},"clientInfo":{"name":"llull-foundation-probe","version":"0.1.0"}}))).unwrap();guard
    }
    #[test] fn authorized_probe_session_is_admitted_but_prompt_never_is() {
        let mut guard=initialized();guard.admit(&frame("session/new",json!({"cwd":WORK,"mcpServers":[admitted_mcp()]}))).unwrap();
        guard.record_session("synthetic-session").unwrap();guard.admit(&frame("session/cancel",json!({"sessionId":"synthetic-session"}))).unwrap();
        assert_eq!(guard.admit(&frame("session/prompt",json!({}))),Err(Fault::Unavailable));
    }
    #[test] fn wire_cannot_override_mcp_command_arguments_environment_or_cwd() {
        for mutation in 0..5 {
            let mut server=admitted_mcp();let mut cwd=WORK;
            match mutation {0=>server.command="/bin/sh".into(),1=>server.args.push("-c".into()),2=>server.env.push(EnvVar{name:"LD_PRELOAD".into(),value:"/tmp/attack.so".into()}),3=>server.env.push(EnvVar{name:"BUZZ_PRIVATE_KEY".into(),value:"synthetic".into()}),_=>cwd="/tmp"}
            assert!(initialized().admit(&frame("session/new",json!({"cwd":cwd,"mcpServers":[server]}))).is_err());
        }
        for method in ["session/steer","session/set_model","tools/call","_unknown"] {assert_eq!(initialized().admit(&frame(method,json!({}))),Err(Fault::Unavailable));}
    }
    #[test] fn inherited_dangerous_keys_are_not_in_launch_declarations() {
        let command=fixed_command(Program::Agent);
        let keys:Vec<_>=command.as_std().get_envs().filter_map(|(k,v)|v.map(|_|k.to_string_lossy().into_owned())).collect();
        for key in ["DATABASE_URL","BUZZ_PRIVATE_KEY","NOSTR_PRIVATE_KEY","SSH_AUTH_SOCK","LD_PRELOAD","LD_LIBRARY_PATH","HTTP_PROXY","HTTPS_PROXY","NODE_OPTIONS","MCP_HOOK_SERVERS","BUZZ_AGENT_SYSTEM_PROMPT_FILE"] {assert!(!keys.iter().any(|k|k==key));}
        assert_eq!(command.as_std().get_program(),AGENT);assert_eq!(command.as_std().get_current_dir(),Some(Path::new(WORK)));
    }
}
