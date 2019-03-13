use parking_lot::Mutex;
use std::collections::HashMap;

use {Database, Delete, Verify, Query};
use types::{Email, Fingerprint, KeyID};
use sync::MutexGuard;
use Result;

#[derive(Debug)]
pub struct Memory {
    update_lock: Mutex<()>,

    fpr: Mutex<HashMap<Fingerprint, String>>,

    fpr_links: Mutex<HashMap<Fingerprint, Fingerprint>>,
    email: Mutex<HashMap<Email, Fingerprint>>,
    kid: Mutex<HashMap<KeyID, Fingerprint>>,
    verify_token: Mutex<HashMap<String, Verify>>,
    delete_token: Mutex<HashMap<String, Delete>>,
}

impl Default for Memory {
    fn default() -> Self {
        Memory {
            update_lock: Mutex::new(()),
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
    fn lock(&self) -> MutexGuard<()> {
        self.update_lock.lock().into()
    }

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

    fn update(
        &self, fpr: &Fingerprint, new: Option<String>,
    ) -> Result<()> {
        let mut fprs = self.fpr.lock();

        if let Some(new) = new {
            fprs.insert(fpr.clone(), new);
        } else {
            fprs.remove(fpr);
        }

        Ok(())
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        use self::Query::*;
        match term {
            ByFingerprint(ref fp) =>
                if self.fpr.lock().contains_key(fp) {
                    Some(fp.clone())
                } else {
                    self.fpr_links.lock().get(fp).map(|fp| fp.clone())
                },
            ByKeyID(ref keyid) =>
                self.kid.lock().get(keyid).map(|fp| fp.clone()),
            ByEmail(ref email) =>
                self.email.lock().get(email).map(|fp| fp.clone()),
        }
    }

    fn link_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        self.fpr_links.lock().insert(from.clone(), fpr.clone());
        Ok(())
    }

    fn unlink_fpr(&self, from: &Fingerprint, _: &Fingerprint) -> Result<()> {
        self.fpr_links.lock().remove(from);
        Ok(())
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        self.email.lock().insert(email.clone(), fpr.clone());
        Ok(())
    }

    fn unlink_email(&self, email: &Email, _: &Fingerprint) -> Result<()> {
        self.email.lock().remove(email);
        Ok(())
    }

    fn link_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        self.kid.lock().insert(kid.clone(), fpr.clone());
        Ok(())
    }

    fn unlink_kid(&self, kid: &KeyID, _: &Fingerprint) -> Result<()> {
        self.kid.lock().remove(kid);
        Ok(())
    }

    // (verified uid, fpr)
    fn pop_verify_token(&self, token: &str) -> Option<Verify> {
        self.verify_token.lock().remove(token)
    }

    // fpr
    fn pop_delete_token(&self, token: &str) -> Option<Delete> {
        self.delete_token.lock().remove(token)
    }

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let fprs = self.fpr.lock();
        let links = self.fpr_links.lock();

        fprs.get(fpr).map(|x| x.clone()).or_else(|| {
            links.get(fpr).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
        })
    }

    fn by_email(&self, email: &Email) -> Option<String> {
        let fprs = self.fpr.lock();
        let by_email = self.email.lock();

        by_email.get(email).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
    }

    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        let fprs = self.fpr.lock();
        let by_kid = self.kid.lock();

        by_kid.get(kid).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
    }
}

impl Memory {
    pub fn new_token() -> String {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        rng.sample_iter(&Alphanumeric).take(43).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test;
    use openpgp::tpk::TPKBuilder;

    #[test]
    fn new() {
        let db = Memory::default();
        let k1 = TPKBuilder::default().add_userid("a@invalid.example.org")
            .generate().unwrap().0;
        let k2 = TPKBuilder::default().add_userid("b@invalid.example.org")
            .generate().unwrap().0;
        let k3 = TPKBuilder::default().add_userid("c@invalid.example.org")
            .generate().unwrap().0;

        assert!(db.merge_or_publish(&k1).unwrap().len() > 0);
        assert!(db.merge_or_publish(&k2).unwrap().len() > 0);
        assert!(!db.merge_or_publish(&k2).unwrap().len() > 0);
        assert!(db.merge_or_publish(&k3).unwrap().len() > 0);
        assert!(!db.merge_or_publish(&k3).unwrap().len() > 0);
        assert!(!db.merge_or_publish(&k3).unwrap().len() > 0);
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

    #[test]
    fn uid_revocation() {
        let mut db = Memory::default();

        test::test_uid_revocation(&mut db);
    }

    #[test]
    fn test_same_email_1() {
        let mut db = Memory::default();

        test::test_same_email_1(&mut db);
    }

    #[test]
    fn test_same_email_2() {
        let mut db = Memory::default();

        test::test_same_email_2(&mut db);
    }
}
