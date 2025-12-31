use std::fs::File;
use anyhow::Result;

pub struct Profiler {
    guard: pprof::ProfilerGuard<'static>,
    path: String,
}

pub fn start(path: &str) -> Profiler {
    tracing::info!("Pprof enabled, output path: {}", path);
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .unwrap();

    Profiler {
        guard,
        path: path.to_string(),
    }
}

pub fn generate_flamegraph(profiler: Profiler) -> Result<()> {
    if let Ok(report) = profiler.guard.report().build() {
        let file = File::create(&profiler.path)?;
        report.flamegraph(file)?;
        tracing::info!("Flamegraph generated at {}", profiler.path);
    }
    Ok(())
}
