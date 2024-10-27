use std::{fmt, fs::File, path::Path, time::SystemTime};
use tracing_subscriber::{
    fmt::{format::Writer, time::FormatTime},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

pub fn create_subscriber(default_directives: &str, log_file_dir: Option<impl AsRef<Path>>) -> eyre::Result<()> {
    let env_filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));
    let format = tracing_subscriber::fmt::format()
        .with_source_location(false)
        .with_file(true)
        .with_timer(Uptime::default());

    let file_format = tracing_subscriber::fmt::format()
        .with_source_location(true)
        .with_file(true)
        .with_timer(Uptime::default())
        .with_ansi(false);

    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .event_format(format)
            .with_filter(env_filter()),
    );

    if let Some(log_file_dir) = log_file_dir {
        let file_subscriber = get_log_file(log_file_dir)?;
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_subscriber)
            .event_format(file_format)
            .with_filter(env_filter());
        subscriber.with(file_layer).init();
    } else {
        subscriber.init();
    }

    Ok(())
}

struct Uptime(std::time::Instant);

impl Default for Uptime {
    fn default() -> Self {
        Uptime(std::time::Instant::now())
    }
}

impl FormatTime for Uptime {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let e = self.0.elapsed();
        let sub_seconds = (e.as_millis() % 1000) / 100;
        write!(w, "{}.{}s", e.as_secs(), sub_seconds)
    }
}

fn get_log_file(log_file_dir: impl AsRef<Path>) -> eyre::Result<File> {
    let now = std::time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;

    let file = log_file_dir.as_ref().join(format!("gbe_proxy_{}.txt", now.as_secs()));
    Ok(std::fs::OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open(file)?)
}
