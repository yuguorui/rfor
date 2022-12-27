mod rules;
mod protos;
mod sniffer;
mod settings;
mod socks5;

mod tproxy;
mod redirect;
mod utils;

use lazy_static::lazy_static;
use redirect::redirect_worker;
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
    let redirect_worker = tokio::spawn(redirect_worker());

    match try_join!(flatten(tproxy_worker), flatten(socks_worker), flatten(redirect_worker)) {
        Ok(_) => {
            unreachable!("shouldn't be here.");
        }
        Err(err) => return Err(err),
    }
}
