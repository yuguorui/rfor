//! Cargo-driven FreeBSD local-traffic integration test.
//!
//! Run with:
//!
//!     cargo test --release --test freebsd_local_traffic -- --ignored --nocapture
//!
//! The harness boots a disposable FreeBSD 15.1 cloud image under Docker +
//! QEMU (tests/freebsd/docker/run.sh), installs the test key over cloud-init,
//! and runs the same in-VM assertions as the manual FreeBSD test.

use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "requires Docker/QEMU and a FreeBSD cloud image; run with --ignored"]
fn freebsd_local_traffic() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = manifest.join("tests/freebsd/docker/run.sh");
    assert!(script.is_file(), "missing harness: {}", script.display());

    eprintln!("harness: {}", script.display());

    let status = Command::new("sh")
        .arg(&script)
        .env("RFOR_ALLOW_IPFW_TEST", "1")
        .status()
        .expect("failed to start the FreeBSD integration harness");

    assert!(
        status.success(),
        "FreeBSD local-traffic integration failed with {status}"
    );
}
