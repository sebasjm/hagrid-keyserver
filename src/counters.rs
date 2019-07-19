use lazy_static::lazy_static;
use rocket_prometheus::prometheus;

use anonymize_utils;

use database::types::Email;

lazy_static! {
    pub static ref KEY_UPLOAD_NEW: Counter =
        Counter::new("key_upload_new", "Uploaded keys (new)");
    pub static ref KEY_UPLOAD_UPDATED: Counter =
        Counter::new("key_upload_updated", "Uploaded keys (updated)");
    pub static ref KEY_UPLOAD_UNCHANGED: Counter =
        Counter::new("key_upload_unchanged", "Uploaded keys (unchanged)");
    pub static ref KEY_UPLOAD_SECRET: Counter =
        Counter::new("key_upload_secret", "Uploaded keys (secret)");
    pub static ref KEY_UPLOAD_ERROR: Counter =
        Counter::new("key_upload_error", "Uploaded keys (error)");

    pub static ref MAIL_SEND_VERIFY: LabelCounter =
        LabelCounter::new("mail_send_verify", "Sent verification mails", &["domain"]);
    pub static ref MAIL_SEND_MANAGE: LabelCounter =
        LabelCounter::new("mail_send_manage", "Sent manage mails", &["domain"]);
    pub static ref MAIL_SEND_WELCOME: LabelCounter =
        LabelCounter::new("mail_send_welcome", "Sent welcome mails", &["domain"]);

    pub static ref KEY_ADDRESS_PUBLISHED: LabelCounter =
        LabelCounter::new("key_address_published", "Verified email addresses", &["domain"]);
    pub static ref KEY_ADDRESS_UNPUBLISHED: LabelCounter =
        LabelCounter::new("key_address_unpublished", "Unpublished email addresses", &["domain"]);
}

pub fn register_counters(registry: &prometheus::Registry) {
    MAIL_SEND_VERIFY.register(registry);
    MAIL_SEND_MANAGE.register(registry);
    MAIL_SEND_WELCOME.register(registry);

    KEY_UPLOAD_NEW.register(registry);
    KEY_UPLOAD_UPDATED.register(registry);
    KEY_UPLOAD_UNCHANGED.register(registry);
    KEY_UPLOAD_SECRET.register(registry);
    KEY_UPLOAD_ERROR.register(registry);
    KEY_ADDRESS_PUBLISHED.register(registry);
    KEY_ADDRESS_UNPUBLISHED.register(registry);
}

pub struct LabelCounter {
    prometheus_counter: prometheus::IntCounterVec,
}

impl LabelCounter {
    fn new(name: &str, help: &str, labels: &[&str]) -> Self {
        let opts = prometheus::Opts::new(name, help);
        let prometheus_counter = prometheus::IntCounterVec::new(opts, labels).unwrap();
        Self { prometheus_counter }
    }

    fn register(&self, registry: &prometheus::Registry) {
        registry.register(Box::new(self.prometheus_counter.clone())).unwrap();
    }

    fn inc(&self, values: &[&str]) {
        self.prometheus_counter.with_label_values(values).inc();
    }

    pub fn inc_email(&self, email: &Email) {
        let anonymized_adddress = anonymize_utils::anonymize_address_fallback(email);
        self.inc(&[&anonymized_adddress]);
    }
}

pub struct Counter {
    prometheus_counter: prometheus::Counter,
}

impl Counter {
    fn new(name: &str, help: &str) -> Self {
        let opts = prometheus::Opts::new(name, help);
        let prometheus_counter = prometheus::Counter::with_opts(opts).unwrap();
        Self { prometheus_counter }
    }

    pub fn inc(&self) {
        self.prometheus_counter.inc();
    }

    fn register(&self, registry: &prometheus::Registry) {
        registry.register(Box::new(self.prometheus_counter.clone())).unwrap();
    }

}

