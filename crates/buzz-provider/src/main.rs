//! Operator CLI and credential-bearing control daemon. Never run in the agent sandbox.
use llull_buzz_provider::{
    api, auth::Registration, HttpNativeOrigin, NativeEventSource, Provider, PublicationPort,
    Publisher,
};
use std::{env, error::Error};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeConfiguration {
    community_id: String,
    private_origin: String,
    public_origin: String,
    service_key_file: std::path::PathBuf,
    relay_public_key: String,
}
async fn native_origin() -> Result<(String, HttpNativeOrigin, nostr::Keys), Box<dyn Error>> {
    let config: NativeConfiguration =
        llull_buzz_wire::parse(&tokio::fs::read(env::var("NATIVE_ORIGIN_CONFIG")?).await?)?;
    use std::os::unix::fs::PermissionsExt;
    let metadata = tokio::fs::metadata(&config.service_key_file).await?;
    if !metadata.is_file() || metadata.len() > 1024 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("native service key must be an owner-only regular file".into());
    }
    let secret = tokio::fs::read_to_string(config.service_key_file).await?;
    let key = nostr::Keys::parse(secret.trim()).map_err(|_| "invalid native service key")?;
    let source = HttpNativeOrigin::new(
        config.community_id.clone(),
        &config.private_origin,
        &config.public_origin,
        key.clone(),
        nostr::PublicKey::from_hex(&config.relay_public_key)
            .map_err(|_| "invalid native relay public key")?,
    )?;
    Ok((config.community_id, source, key))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--help") || args.is_empty() {
        println!("llull-buzz-provider: migrate | register FILE [EXPECTED_DIGEST] | service-active CONSUMER true|false EXPECTED_DIGEST | advance-recovery-epoch EXPECTED | native-probe CHANNEL EVENT_ID | serve\nRequired trusted environment for DB commands: DATABASE_URL, PUBLIC_ORIGIN (https origin), EXTERNAL_RECOVERY_EPOCH. NATIVE_ORIGIN_CONFIG is required for native-probe and optional for serve. Optional BIND_ADDR (default 127.0.0.1:8080). No implicit migrations or registrations.");
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("native-probe") && args.len() == 3 {
        let (community, source, _) = native_origin().await?;
        let audience = source.audience(&community, &args[1]).await?;
        let bytes = source.event(&community, &args[1], &args[2]).await?;
        let event = llull_buzz_provider::native::event(&bytes)?;
        println!(
            "{}",
            serde_json::json!({
                "native_event_id": event.id.to_hex(),
                "native_event_sha256": llull_buzz_wire::sha256(&bytes),
                "audience_revision": audience.revision,
                "audience_member_count": audience.members.len(),
                "scope": "fixed native origin read; no provider command admission"
            })
        );
        return Ok(());
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&env::var("DATABASE_URL")?)
        .await?;
    let provider = Provider::new(
        pool,
        &env::var("PUBLIC_ORIGIN")?,
        env::var("EXTERNAL_RECOVERY_EPOCH")?.parse()?,
    )?;
    match args.first().map(String::as_str) {
        Some("migrate") if args.len() == 1 => provider.migrate().await?,
        Some("register") if (2..=3).contains(&args.len()) => {
            let bytes = tokio::fs::read(&args[1]).await?;
            let registration: Registration = llull_buzz_wire::parse(&bytes)?;
            println!(
                "{}",
                provider
                    .register(registration, args.get(2).map(String::as_str))
                    .await?
            );
        }
        Some("service-active") if args.len() == 4 => {
            provider
                .set_service_active(&args[1], args[2].parse()?, &args[3])
                .await?
        }
        Some("advance-recovery-epoch") if args.len() == 2 => println!(
            "{}",
            provider.advance_recovery_epoch(args[1].parse()?).await?
        ),
        Some("serve") if args.len() == 1 => {
            let mut router = axum::Router::new();
            let mut surfaces = api::ConfiguredSurfaces::default();
            if env::var_os("NATIVE_ORIGIN_CONFIG").is_some() {
                let (_, source, key) = native_origin().await?;
                let source = std::sync::Arc::new(source);
                let publisher = std::sync::Arc::new(Publisher::new(
                    source.clone(),
                    key,
                    source.public_origin().as_str(),
                )?);
                router = router
                    .merge(api::native_routes(provider.clone(), source))
                    .merge(api::publication_routes(provider.clone(), publisher));
                surfaces.native_intake = true;
                surfaces.publication_delivery = true;
            }
            router = api::router_with_surfaces(provider.clone(), surfaces).merge(router);
            let address = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let listener = tokio::net::TcpListener::bind(address).await?;
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        _ => return Err("unsupported operator command; use --help".into()),
    }
    Ok(())
}
