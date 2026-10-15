//! One invocation clock; failures remain sticky through final owned cleanup.
use super::{deny, Result};
use futures_util::FutureExt;
pub(crate) type Cancellation =
    futures_util::future::Shared<futures_util::future::BoxFuture<'static, ()>>;
pub const MAX_ELAPSED_US: i64 = 20_000_000;
pub struct Budget {
    start: i64,
    last: i64,
    expires: i64,
    failed: bool,
    cancellation: Option<Cancellation>,
}
impl Budget {
    pub fn new(now: i64, expires: i64) -> Result<Self> {
        if now < 0 || expires <= now {
            return Err(deny("clock_or_deadline"));
        }
        Ok(Self {
            start: now,
            last: now,
            expires,
            failed: false,
            cancellation: None,
        })
    }
    pub(crate) fn watch(&mut self, cancellation: Cancellation) {
        self.cancellation = Some(cancellation);
    }
    pub(crate) fn cancellation(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let cancellation = self.cancellation.clone();
        async move {
            match cancellation {
                Some(signal) => signal.await,
                None => std::future::pending().await,
            }
        }
    }
    pub fn sample(&mut self, now: i64) -> Result<i64> {
        if self
            .cancellation
            .clone()
            .is_some_and(|signal| signal.now_or_never().is_some())
        {
            self.failed = true;
            return Err(super::InspectionError::Unknown {
                code: "inspection_cancelled",
                first: None,
                cleanup: Vec::new(),
            });
        }
        if self.failed
            || now < self.last
            || now
                .checked_sub(self.start)
                .is_none_or(|v| v > MAX_ELAPSED_US)
            || now >= self.expires
        {
            self.failed = true;
            return Err(deny("clock_or_deadline"));
        }
        self.last = now;
        Ok(now)
    }
    pub fn constrain(&mut self, expires: i64) -> Result<()> {
        self.expires = self.expires.min(expires);
        self.sample(self.last).map(|_| ())
    }
    pub fn remaining(&self) -> Result<std::time::Duration> {
        if self.failed {
            return Err(deny("clock_or_deadline"));
        }
        let cap = MAX_ELAPSED_US
            .checked_sub(self.last - self.start)
            .ok_or_else(|| deny("clock_or_deadline"))?
            .min(self.expires - self.last);
        if cap <= 0 {
            return Err(deny("clock_or_deadline"));
        }
        Ok(std::time::Duration::from_micros(cap as u64))
    }
}
pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp_micros()
}
