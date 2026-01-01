use std::fs::File;

pub struct Profiler {
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    guard: pprof::ProfilerGuard<'static>,
    pub path: String,
}

pub fn start(path: &str) -> Profiler {
    tracing::info!("Pprof enabled, output path: {}", path);

    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))]
    {
        let builder = pprof::ProfilerGuardBuilder::default().frequency(1000);

        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let builder = builder.blocklist(&["libc", "libgcc", "pthread", "vdso"]);

        let guard = builder.build().unwrap();

        Profiler {
            guard,
            path: path.to_string(),
        }
    }

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        tracing::warn!("Pprof is not supported on this architecture.");
        Profiler {
            path: path.to_string(),
        }
    }
}

impl Drop for Profiler {
    fn drop(&mut self) {
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        ))]
        {
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
}
