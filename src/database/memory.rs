use std::collections::HashMap;
use parking_lot::Mutex;

use openpgp::UserID;
use base64;

use database::{Verify, Delete, Fingerprint, Database};
use Result;

pub struct Memory {
    fpr: Mutex<HashMap<Fingerprint, Box<[u8]>>>,
    userid: Mutex<HashMap<String, Fingerprint>>,
    verify_token: Mutex<HashMap<String, Verify>>,
    delete_token: Mutex<HashMap<String, Delete>>,
}

impl Default for Memory {
    fn default() -> Self {
        Memory{
            fpr: Mutex::new(HashMap::default()),
            userid: Mutex::new(HashMap::default()),
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

    fn link_userid(&self, uid: &UserID, fpr: &Fingerprint) {
        let uid = base64::encode_config(uid.userid(), base64::URL_SAFE);
        self.userid.lock().insert(uid.to_string(), fpr.clone());
    }

    fn unlink_userid(&self, uid: &UserID, _: &Fingerprint) {
        let uid = base64::encode_config(uid.userid(), base64::URL_SAFE);
        self.userid.lock().remove(&uid.to_string());
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
        self.fpr.lock().get(fpr).map(|x| x.clone())
    }

    fn by_uid(&self, uid: &str) -> Option<Box<[u8]>> {
        let userid = self.userid.lock();
        let fprs = self.fpr.lock();

        userid.get(uid).and_then(|fpr| fprs.get(fpr).map(|x| x.clone()))
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
    use openpgp::tpk::TPKBuilder;
    use database::test;

    #[test]
    fn new() {
        let mut db = Memory::default();
        let k1 = TPKBuilder::default().add_userid("a").generate().unwrap();
        let k2 = TPKBuilder::default().add_userid("b").generate().unwrap();
        let k3 = TPKBuilder::default().add_userid("c").generate().unwrap();

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
}
