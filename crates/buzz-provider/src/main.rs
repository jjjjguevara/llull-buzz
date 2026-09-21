//! Operator CLI and credential-bearing control daemon. Never run in the agent sandbox.
use llull_buzz_provider::{api, auth::Registration, Provider};
use std::{env, error::Error};
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--help") || args.is_empty() {
        println!("llull-buzz-provider: migrate | register FILE [EXPECTED_DIGEST] | service-active CONSUMER true|false EXPECTED_DIGEST | advance-recovery-epoch EXPECTED | serve\nRequired trusted environment: DATABASE_URL, PUBLIC_ORIGIN (https origin), EXTERNAL_RECOVERY_EPOCH. Optional BIND_ADDR (default 127.0.0.1:8080). No implicit migrations or registrations.");
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
            let address = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let listener = tokio::net::TcpListener::bind(address).await?;
            axum::serve(listener, api::router(provider))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        _ => return Err("unsupported operator command; use --help".into()),
    }
    Ok(())
}
