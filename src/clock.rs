//! Horloge de l'application : le code ne lit jamais l'heure système directement, pour que les
//! tests maîtrisent expirations et fenêtres de débit.

use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;

    /// Instant courant en secondes Unix (protocole).
    fn unix(&self) -> i64 {
        self.now().timestamp()
    }
}

/// Heure système.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Horloge réglée à la main (tests).
pub struct ManualClock(Mutex<DateTime<Utc>>);

impl ManualClock {
    pub fn new(at: DateTime<Utc>) -> Self {
        Self(Mutex::new(at))
    }

    pub fn set(&self, at: DateTime<Utc>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = at;
    }

    pub fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *now += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}
