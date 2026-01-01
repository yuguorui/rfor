use std::fs::File;

pub struct Profiler {
    guard: pprof::ProfilerGuard<'static>,
    pub path: String,
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

impl Drop for Profiler {
    fn drop(&mut self) {
        tracing::info!("Stopping profiler and generating report...");
        match self.guard.report().build() {
            Ok(report) => match File::create(&self.path) {
                Ok(file) => {
                    if let Err(e) = report.flamegraph(file) {
                        tracing::error!("Failed to generate flamegraph: {}", e);
                    } else {
                        tracing::info!("Flamegraph generated at {}", self.path);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to create flamegraph file '{}': {}", self.path, e)
                }
            },
            Err(e) => tracing::error!("Failed to build pprof report: {}", e),
        }
    }
}
