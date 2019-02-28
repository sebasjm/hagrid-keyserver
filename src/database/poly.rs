use database::{Database, Delete, Filesystem, Memory, Verify, Query};
use Result;
use types::{Email, Fingerprint, KeyID};
use parking_lot::MutexGuard;

pub enum Polymorphic {
    Memory(Memory),
    Filesystem(Filesystem),
}

impl Database for Polymorphic {
    fn lock(&self) -> MutexGuard<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.lock(),
            &Polymorphic::Filesystem(ref db) => db.lock(),
        }
    }

    fn new_verify_token(&self, payload: Verify) -> Result<String> {
        match self {
            &Polymorphic::Memory(ref db) => db.new_verify_token(payload),
            &Polymorphic::Filesystem(ref db) => db.new_verify_token(payload),
        }
    }

    fn new_delete_token(&self, payload: Delete) -> Result<String> {
        match self {
            &Polymorphic::Memory(ref db) => db.new_delete_token(payload),
            &Polymorphic::Filesystem(ref db) => db.new_delete_token(payload),
        }
    }

    fn update(
        &self, fpr: &Fingerprint, new: Option<String>,
    ) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => {
                db.update(fpr, new)
            }
            &Polymorphic::Filesystem(ref db) => {
                db.update(fpr, new)
            }
        }
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        match self {
            &Polymorphic::Memory(ref db) =>
                db.lookup_primary_fingerprint(term),
            &Polymorphic::Filesystem(ref db) =>
                db.lookup_primary_fingerprint(term),
        }
    }

    fn link_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.link_fpr(from, fpr),
            &Polymorphic::Filesystem(ref db) => db.link_fpr(from, fpr),
        }
    }

    fn unlink_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.unlink_fpr(from, fpr),
            &Polymorphic::Filesystem(ref db) => db.unlink_fpr(from, fpr),
        }
    }

    fn link_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.link_kid(kid, fpr),
            &Polymorphic::Filesystem(ref db) => db.link_kid(kid, fpr),
        }
    }

    fn unlink_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.unlink_kid(kid, fpr),
            &Polymorphic::Filesystem(ref db) => db.unlink_kid(kid, fpr),
        }
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.link_email(email, fpr),
            &Polymorphic::Filesystem(ref db) => db.link_email(email, fpr),
        }
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        match self {
            &Polymorphic::Memory(ref db) => db.unlink_email(email, fpr),
            &Polymorphic::Filesystem(ref db) => db.unlink_email(email, fpr),
        }
    }

    fn pop_verify_token(&self, token: &str) -> Option<Verify> {
        match self {
            &Polymorphic::Memory(ref db) => db.pop_verify_token(token),
            &Polymorphic::Filesystem(ref db) => db.pop_verify_token(token),
        }
    }

    fn pop_delete_token(&self, token: &str) -> Option<Delete> {
        match self {
            &Polymorphic::Memory(ref db) => db.pop_delete_token(token),
            &Polymorphic::Filesystem(ref db) => db.pop_delete_token(token),
        }
    }

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        match self {
            &Polymorphic::Memory(ref db) => db.by_fpr(fpr),
            &Polymorphic::Filesystem(ref db) => db.by_fpr(fpr),
        }
    }

    fn by_email(&self, email: &Email) -> Option<String> {
        match self {
            &Polymorphic::Memory(ref db) => db.by_email(email),
            &Polymorphic::Filesystem(ref db) => db.by_email(email),
        }
    }

    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        match self {
            &Polymorphic::Memory(ref db) => db.by_kid(kid),
            &Polymorphic::Filesystem(ref db) => db.by_kid(kid),
        }
    }
}
