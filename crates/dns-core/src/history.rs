use crate::models::{DNSResolutionRecord, ResolutionSource};
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub const MAX_HISTORY_RECORDS: usize = 500;

type OnRecordCallback = Arc<dyn Fn(&DNSResolutionRecord) + Send + Sync>;

#[derive(Default)]
struct HistoryState {
    records: VecDeque<DNSResolutionRecord>,
    total_resolved_count: u64,
    callback: Option<OnRecordCallback>,
}

#[derive(Clone)]
pub struct DNSHistoryStore {
    inner: Arc<Mutex<HistoryState>>,
}

impl Default for DNSHistoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DNSHistoryStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HistoryState::default())),
        }
    }

    pub fn set_on_record<F>(&self, cb: F)
    where
        F: Fn(&DNSResolutionRecord) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.inner.lock() {
            guard.callback = Some(Arc::new(cb));
        }
    }

    pub fn log_resolution(
        &self,
        domain: String,
        qtype: String,
        source: ResolutionSource,
        server_name: String,
        latency_ms: u64,
        resolved_ips: Vec<String>,
        is_success: bool,
    ) -> DNSResolutionRecord {
        let record = DNSResolutionRecord {
            id: Uuid::new_v4().to_string(),
            timestamp_ms: Utc::now().timestamp_millis(),
            domain,
            qtype,
            source,
            server_name,
            latency_ms,
            resolved_ips,
            is_success,
        };

        let cb = {
            let mut guard = self.inner.lock().unwrap();
            if guard.records.len() >= MAX_HISTORY_RECORDS {
                guard.records.pop_back();
            }
            guard.records.push_front(record.clone());
            guard.total_resolved_count += 1;
            guard.callback.clone()
        };

        if let Some(cb) = cb {
            cb(&record);
        }

        record
    }

    pub fn records(&self) -> Vec<DNSResolutionRecord> {
        self.inner
            .lock()
            .map(|g| g.records.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn stats(&self) -> (u64, usize) {
        self.inner
            .lock()
            .map(|g| (g.total_resolved_count, g.records.len()))
            .unwrap_or((0, 0))
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.records.clear();
        }
    }
}
