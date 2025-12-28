mod rules;
mod protos;
mod sniffer;
mod settings;
mod socks5;

mod tproxy;
mod redirect;
mod utils;

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

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let tproxy_worker = tokio::spawn(tproxy::tproxy_worker());
    let socks_worker = tokio::spawn(socks5::socks5_worker());
    let redirect_worker = tokio::spawn(redirect_worker());

    match try_join!(flatten(tproxy_worker), flatten(socks_worker), flatten(redirect_worker)) {
        Ok(_) => {
            unreachable!("shouldn't be here.");
        }
        Err(err) => return Err(err),
    }
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
