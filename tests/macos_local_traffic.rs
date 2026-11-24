//! Cargo-driven macOS `utun` local-traffic and forwarded-traffic E2E test.
//!
//! Run with:
//!
//!     cargo test --release --test macos_local_traffic -- --ignored --nocapture
//!
//! The harness boots disposable macOS VMs under Cirrus Labs' `tart`
//! (`tests/macos/tart/run.sh`) and verifies both `local-traffic: true`
//! (host-local TCP/UDP/DNS/QUIC + restart cleanup soak) and
//! `local-traffic: false` (two-VM PF `route-to utun` forwarded traffic).

use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires Apple Silicon macOS with tart and a cached macOS guest image; run with --ignored"]
fn macos_local_traffic() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest.join("tests/macos/tart/run.sh");
    assert!(script.is_file(), "missing harness: {}", script.display());

    eprintln!("harness: {}", script.display());

    let status = Command::new("sh")
        .arg(&script)
        .env("RFOR_ALLOW_UTUN_TEST", "1")
        .status()
        .expect("failed to start the macOS tart integration harness");

    assert!(
        status.success(),
        "macOS utun integration failed with {status}"
    );
}
