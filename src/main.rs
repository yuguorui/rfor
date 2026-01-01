mod rules;
mod protos;
mod sniffer;
mod settings;
mod socks5;
mod stats;

mod tproxy;
mod redirect;
mod utils;
mod profiler;

use std::sync::OnceLock;
use redirect::redirect_worker;
use tokio::task::JoinHandle;
use tokio::try_join;

use std::sync::Arc;
use tokio::sync::RwLock;

use settings::Settings;

use anyhow::anyhow;
use anyhow::Result;
use tracing::error;
use tracing_subscriber;

static SETTINGS: OnceLock<Arc<RwLock<Settings>>> = OnceLock::new();

pub fn get_settings() -> &'static Arc<RwLock<Settings>> {
    SETTINGS.get_or_init(|| {
        Arc::new(RwLock::const_new(Settings::new().expect("Failed to load settings")))
    })
}

async fn flatten(handle: JoinHandle<Result<()>>) -> Result<()> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => {
            error!("Task handling failed: {:?}", err);
            Err(anyhow!("handling failed with error: {:?}", err))
        }
    }
}

async fn reload_worker(
    profiler_store: Arc<std::sync::Mutex<Option<profiler::Profiler>>>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            sighup.recv().await;
            tracing::info!("Received SIGHUP, reloading settings...");

            let new_settings = match Settings::load() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to reload settings: {}", e);
                    continue;
                }
            };

            let new_pprof_config = new_settings.pprof.clone();

            *get_settings().write().await = new_settings;
            tracing::info!("Settings reloaded successfully.");


            // Handle Profiler update
            let mut store = profiler_store.lock().unwrap();
            let current_path = store.as_ref().map(|p| p.path.clone());

            if current_path != new_pprof_config {
                // Configuration changed

                // 1. Stop old profiler if exists
                // Drop will handle flamegraph generation
                let _ = store.take();

                // 2. Start new profiler if enabled
                if let Some(path) = new_pprof_config {
                    tracing::info!("Starting profiler at {}", path);
                    *store = Some(profiler::start(&path));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Suppress unused variable warning on non-unix
        let _ = profiler_store;
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let settings = get_settings().read().await;
    let profiler = settings.pprof.as_ref().map(|path| profiler::start(path));
    drop(settings);

    let profiler_store = Arc::new(std::sync::Mutex::new(profiler));

    let tproxy_worker = tokio::spawn(tproxy::tproxy_worker());
    let socks_worker = tokio::spawn(socks5::socks5_worker());
    let redirect_worker = tokio::spawn(redirect_worker());
    let stats_worker = tokio::spawn(stats::stats_logger_worker());
    let reload_worker = tokio::spawn(reload_worker(profiler_store.clone()));

    tokio::select! {
        res = async {
            try_join!(
                flatten(tproxy_worker),
                flatten(socks_worker),
                flatten(redirect_worker),
                flatten(stats_worker),
                flatten(reload_worker)
            )
        } => {
            match res {
                Ok(_) => {
                    unreachable!("shouldn't be here.");
                }
                Err(err) => return Err(err),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down...");
        }
    }

    Ok(())
}

fn init_logging() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rfor=info".into());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();
}
