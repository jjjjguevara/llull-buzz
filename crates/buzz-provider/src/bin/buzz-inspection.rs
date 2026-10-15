//! Fixed private local command. No caller roles/paths/credentials or HTTP route.
#![forbid(unsafe_code)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("inspection refused: arguments unsupported");
        std::process::exit(2);
    }
    // Install both handlers before opening an input, SQL connection or output.
    let signals = (
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
    );
    let (Ok(mut interrupt), Ok(mut terminate)) = signals else {
        eprintln!("inspection refused: signal registration unavailable");
        std::process::exit(1);
    };
    let result = llull_buzz_provider::inspection::port::run_local(async move {
        tokio::select! { _ = interrupt.recv() => (), _ = terminate.recv() => () }
    })
    .await;
    match result {
        Ok(receipt) => println!("{}", receipt.filename),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
