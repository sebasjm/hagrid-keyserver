use errors::Result;
use database::{Verify, Delete, Database, Filesystem, Memory};
use types::{Fingerprint, Email};

pub enum Polymorphic {
    Memory(Memory),
    Filesystem(Filesystem),
}

impl Database for Polymorphic {
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

    fn compare_and_swap(&self, fpr: &Fingerprint, present: Option<&[u8]>, new: Option<&[u8]>) -> Result<bool> {
        match self {
            &Polymorphic::Memory(ref db) => db.compare_and_swap(fpr, present, new),
            &Polymorphic::Filesystem(ref db) => db.compare_and_swap(fpr, present, new),
        }
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) {
        match self {
            &Polymorphic::Memory(ref db) => db.link_email(email, fpr),
            &Polymorphic::Filesystem(ref db) => db.link_email(email, fpr),
        }
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) {
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

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>> {
        match self {
            &Polymorphic::Memory(ref db) => db.by_fpr(fpr),
            &Polymorphic::Filesystem(ref db) => db.by_fpr(fpr),
        }
    }

    fn by_email(&self, email: &Email) -> Option<Box<[u8]>> {
        match self {
            &Polymorphic::Memory(ref db) => db.by_email(email),
            &Polymorphic::Filesystem(ref db) => db.by_email(email),
        }
    }
}
