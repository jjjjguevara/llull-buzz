//! SDK-native, non-consequential MCP compatibility probe. No business tool exists.
use rmcp::{model::{ServerCapabilities,ServerInfo},ServerHandler,ServiceExt};
#[derive(Clone)] struct Probe;
impl ServerHandler for Probe {
    fn get_info(&self)->ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().build()).with_instructions("Foundation protocol probe only. Consequential tools and publication are unavailable.".to_string())
    }
}
#[tokio::main] async fn main()->Result<(),Box<dyn std::error::Error>> {
    Probe.serve(rmcp::transport::stdio()).await?.waiting().await?;Ok(())
}
