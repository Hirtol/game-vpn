use std::{fmt};
use tracing::Subscriber;
use tracing_subscriber::{
    fmt::{format::Writer, time::FormatTime},
    layer::SubscriberExt,
    EnvFilter, Layer,
};

pub fn create_subscriber(default_directives: &str) -> impl Subscriber {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));

    let format = tracing_subscriber::fmt::format()
        .with_source_location(false)
        .with_file(false)
        .with_timer(Uptime::default());

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(format)
                .with_filter(env_filter),
        )
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
