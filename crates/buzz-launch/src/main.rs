//! Synthetic protocol probe. Run ONLY in the disposable test container documented
//! in LOCAL-REVIEW.md so teardown kills the entire ACP/MCP process namespace.
use llull_buzz_launch::{AcpGuard,ImageIdentity,Program,admitted_mcp,checked_command,WORK};
use llull_buzz_wire::{canonical,parse,Fault,MAX_BYTES};
use serde_json::{json,Value};
use tokio::io::{AsyncBufRead,AsyncBufReadExt,AsyncWriteExt,BufReader};
use std::time::Duration;
async fn line<R:AsyncBufRead+Unpin>(reader:&mut R)->Result<Vec<u8>,Box<dyn std::error::Error>> {
    let mut bytes=Vec::new();
    loop {
        let buffer=reader.fill_buf().await?;
        if buffer.is_empty() {return Err("upstream EOF before response".into());}
        let count=buffer.iter().position(|b|*b==b'\n').map(|i|i+1).unwrap_or(buffer.len());
        if bytes.len()+count>MAX_BYTES {return Err(Fault::TooLarge.into());}
        let end=buffer[count-1]==b'\n';bytes.extend_from_slice(&buffer[..count]);reader.consume(count);
        if end {return Ok(bytes);}
    }
}
async fn exchange(guard:&mut AcpGuard,input:&mut tokio::process::ChildStdin,output:&mut BufReader<tokio::process::ChildStdout>,id:u64,method:&str,params:Value)->Result<Value,Box<dyn std::error::Error>> {
    let bytes=guard.admit(&canonical(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?)?;
    input.write_all(&bytes).await?;input.write_all(b"\n").await?;input.flush().await?;
    let response:Value=parse(&tokio::time::timeout(Duration::from_secs(15),line(output)).await??)?;
    if response.get("id")!=Some(&json!(id)) || response.get("error").is_some() {return Err("upstream protocol incompatibility; retain response locally for review".into());}
    response.get("result").cloned().ok_or_else(||"missing upstream result".into())
}
#[tokio::main] async fn main()->Result<(),Box<dyn std::error::Error>> {
    if std::env::args().skip(1).collect::<Vec<_>>()!=["probe"] {return Err("only `probe` is available; live restricted activation is unavailable".into());}
    let identity=ImageIdentity::load()?;identity.verify()?;
    let mut child=checked_command(&identity,Program::Agent)?.spawn()?;
    // Inspect the actual child after exec, not only Command's declared env map.
    let pid=child.id().ok_or("missing child pid")?;
    let environment=tokio::fs::read(format!("/proc/{pid}/environ")).await?;
    let mut actual=std::collections::BTreeMap::new();
    for entry in environment.split(|b|*b==0).filter(|b|!b.is_empty()) {
        let entry=std::str::from_utf8(entry)?;let (key,value)=entry.split_once('=').ok_or("invalid child environment")?;actual.insert(key.to_string(),value.to_string());
    }
    let expected:std::collections::BTreeMap<String,String>=llull_buzz_launch::environment().into_iter().map(|(k,v)|(k.into(),v.into())).collect();
    if actual!=expected {let _=child.kill().await;let _=child.wait().await;return Err("actual child environment differs from closed launch policy".into());}
    let mut input=child.stdin.take().ok_or("missing child stdin")?;
    let mut output=BufReader::new(child.stdout.take().ok_or("missing child stdout")?);
    let result=async {
        let mut guard=AcpGuard::default();
        let init=exchange(&mut guard,&mut input,&mut output,1,"initialize",json!({"protocolVersion":2,"clientCapabilities":{},"clientInfo":{"name":"llull-foundation-probe","version":"0.1.0"}})).await?;
        if init.get("protocolVersion")!=Some(&json!(2)) {return Err::<(),Box<dyn std::error::Error>>("ACP protocol version mismatch".into());}
        let session=exchange(&mut guard,&mut input,&mut output,2,"session/new",json!({"cwd":WORK,"mcpServers":[admitted_mcp()]})).await?;
        let id=session.get("sessionId").and_then(Value::as_str).ok_or("missing sessionId")?;guard.record_session(id)?;
        exchange(&mut guard,&mut input,&mut output,3,"session/cancel",json!({"sessionId":id})).await?;
        Ok(())
    }.await;
    let _=child.kill().await;let _=child.wait().await;result?;
    let status=tokio::time::timeout(Duration::from_secs(10),checked_command(&identity,Program::AcpHelp)?.status()).await??;
    if !status.success() {return Err("pinned buzz-acp CLI probe failed".into());}
    println!("{{\"probe\":\"ACP2-session-MCP\",\"inheritance_checked\":true,\"model_calls\":0,\"restricted_profile_active\":false}}");Ok(())
}
