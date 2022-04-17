mod rules;
mod protos;
mod settings;
mod socks5;

mod tproxy;
mod utils;

use lazy_static::lazy_static;
use tokio::task::JoinHandle;
use tokio::try_join;

use std::sync::Arc;
use tokio::sync::RwLock;

use settings::Settings;

use anyhow::anyhow;
use anyhow::Result;

lazy_static! {
    static ref SETTINGS: Arc<RwLock<Settings>> =
        Arc::new(RwLock::const_new(Settings::new().unwrap()));
}

async fn flatten(handle: JoinHandle<Result<()>>) -> Result<()> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(anyhow!("handling failed with error: {:?}", err)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let tproxy_worker = tokio::spawn(tproxy::tproxy_worker());
    let socks_worker = tokio::spawn(socks5::socks5_worker());

    match try_join!(flatten(tproxy_worker), flatten(socks_worker)) {
        Ok(_) => {
            unreachable!("shouldn't be here.");
        }
        Err(err) => return Err(err),
    }
}
