use std::collections::HashMap;
use parking_lot::Mutex;

use database::{Verify, Delete, Database};
use types::{Email, Fingerprint, KeyID};
use Result;

#[derive(Debug)]
pub struct Memory {
    fpr: Mutex<HashMap<Fingerprint, Box<[u8]>>>,
    fpr_links: Mutex<HashMap<Fingerprint, Fingerprint>>,
    email: Mutex<HashMap<Email, Fingerprint>>,
    kid: Mutex<HashMap<KeyID, Fingerprint>>,
    verify_token: Mutex<HashMap<String, Verify>>,
    delete_token: Mutex<HashMap<String, Delete>>,
}

impl Default for Memory {
    fn default() -> Self {
        Memory{
            fpr: Mutex::new(HashMap::default()),
            fpr_links: Mutex::new(HashMap::default()),
            kid: Mutex::new(HashMap::default()),
            email: Mutex::new(HashMap::default()),
            verify_token: Mutex::new(HashMap::default()),
            delete_token: Mutex::new(HashMap::default()),
        }
    }
}

impl Database for Memory {
    fn new_verify_token(&self, payload: Verify) -> Result<String> {
        let token = Self::new_token();

        self.verify_token.lock().insert(token.clone(), payload);
        Ok(token)
    }

    fn new_delete_token(&self, payload: Delete) -> Result<String> {
        let token = Self::new_token();

        self.delete_token.lock().insert(token.clone(), payload);
        Ok(token)
    }

    fn compare_and_swap(&self, fpr: &Fingerprint, present: Option<&[u8]>, new: Option<&[u8]>) -> Result<bool> {
        let mut fprs = self.fpr.lock();

        if fprs.get(fpr).map(|x| &x[..]) == present {
            if let Some(new) = new {
                fprs.insert(fpr.clone(), new.into());
            } else {
                fprs.remove(fpr);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn link_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) {
        self.fpr_links.lock().insert(from.clone(), fpr.clone());
    }

    fn unlink_fpr(&self, from: &Fingerprint, _: &Fingerprint) {
        self.fpr_links.lock().remove(from);
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) {
        self.email.lock().insert(email.clone(), fpr.clone());
    }

    fn unlink_email(&self, email: &Email, _: &Fingerprint) {
        self.email.lock().remove(email);
    }

    fn link_kid(&self, kid: &KeyID, fpr: &Fingerprint) {
        self.kid.lock().insert(kid.clone(), fpr.clone());
    }

    fn unlink_kid(&self, kid: &KeyID, _: &Fingerprint) {
        self.kid.lock().remove(kid);
    }

    // (verified uid, fpr)
    fn pop_verify_token(&self, token: &str) -> Option<Verify> {
        self.verify_token.lock().remove(token)
    }

    // fpr
    fn pop_delete_token(&self, token: &str) -> Option<Delete> {
        self.delete_token.lock().remove(token)
    }

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>> {
        let fprs = self.fpr.lock();
        let links = self.fpr_links.lock();

        fprs.get(fpr).map(|x| x.clone()).or_else(|| {
            links.get(fpr).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
        })
    }

    fn by_email(&self, email: &Email) -> Option<Box<[u8]>> {
        let fprs = self.fpr.lock();
        let by_email = self.email.lock();

        by_email.get(email).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
    }

    fn by_kid(&self, kid: &KeyID) -> Option<Box<[u8]>> {
        let fprs = self.fpr.lock();
        let by_kid = self.kid.lock();

        by_kid.get(kid).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
    }
}

impl Memory {
    pub fn new_token() -> String {
        use rand::{thread_rng, Rng};
        use rand::distributions::Alphanumeric;

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        rng.sample_iter(&Alphanumeric).take(43).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::tpk::TPKBuilder;
    use database::test;

    #[test]
    fn new() {
        let db = Memory::default();
        let k1 = TPKBuilder::default().add_userid("a").generate().unwrap().0;
        let k2 = TPKBuilder::default().add_userid("b").generate().unwrap().0;
        let k3 = TPKBuilder::default().add_userid("c").generate().unwrap().0;

        assert!(db.merge_or_publish(k1).unwrap().len() > 0);
        assert!(db.merge_or_publish(k2.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k2).unwrap().len() > 0);
        assert!(db.merge_or_publish(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k3).unwrap().len() > 0);
    }

    #[test]
    fn uid_verification() {
        let mut db = Memory::default();

        test::test_uid_verification(&mut db);
    }

    #[test]
    fn subkey_lookup() {
        let mut db = Memory::default();

        test::test_subkey_lookup(&mut db);
    }

    #[test]
    fn kid_lookup() {
        let mut db = Memory::default();

        test::test_kid_lookup(&mut db);
    }
}
