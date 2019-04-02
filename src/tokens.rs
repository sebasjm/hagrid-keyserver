use sealed_state::SealedState;

use std::time::SystemTime;

use database::types::{Fingerprint};
use serde_json;

const REVISION: u8 = 1;

pub struct Service {
    sealed_state: SealedState,
    validity: u64,
}

#[derive(Serialize,Deserialize)]
struct Token {
    #[serde(rename = "f")]
    fpr: Fingerprint,
    #[serde(rename = "c")]
    creation: u64,
    #[serde(rename = "r")]
    revision: u8,
}

impl Service {
    pub fn init(secret: &str, validity: u64) -> Self {
        let sealed_state = SealedState::new(secret);
        Service { sealed_state, validity }
    }

    pub fn create(&self, fpr: &Fingerprint) -> String {
        let creation = current_time();
        let token = Token { fpr: fpr.clone(), creation, revision: REVISION };
        let token_serialized = serde_json::to_string(&token).unwrap();

        let token_sealed = self.sealed_state.seal(&token_serialized);

        base64::encode_config(&token_sealed, base64::URL_SAFE_NO_PAD)
    }

    pub fn check(&self, token_encoded: &str) -> Result<Fingerprint, String> {
        let token_sealed = base64::decode_config(&token_encoded, base64::URL_SAFE_NO_PAD).map_err(|_| "invalid b64")?;
        let token_str = self.sealed_state.unseal(token_sealed)?;
        let token: Token = serde_json::from_str(&token_str)
            .map_err(|_| "failed to deserialize")?;

        let elapsed = current_time() - token.creation;
        if elapsed > self.validity {
            Err("Token has expired!")?;
        }

        Ok(token.fpr)
    }

}

#[cfg(not(test))]
fn current_time() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
fn current_time() -> u64 {
    12345678
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_check() {
        let fpr = "D4AB192964F76A7F8F8A9B357BD18320DEADFA11".parse().unwrap();
        let mt = Service::init("secret", 60);
        let token = mt.create(&fpr);
        // println!("{}", &token);
        // assert!(false);

        let check_result = mt.check(&token);

        assert_eq!(Ok(fpr), check_result);
    }

    #[test]
    fn test_ok() {
        // {"f":"D4AB192964F76A7F8F8A9B357BD18320DEADFA11","c":12345658,"r":1}
        let fpr = "D4AB192964F76A7F8F8A9B357BD18320DEADFA11".parse().unwrap();
        let token = "KkhDt1quo1I1l3OPazSXKAmuNL6LLluhnRR6eQPsLruJ4URo-AKp4YGMsVlkDvj3NLvALt6Omp7vLzMbdv_DCus6oL3X-CSyQs9AFO6f5QMaseyAPtafKMDtDW2c1_Q";
        let mt = Service::init("secret", 60);

        let check_result = mt.check(token);

        assert_eq!(Ok(fpr), check_result);
    }

    #[test]
    fn test_expired() {
        // {"f":"D4AB192964F76A7F8F8A9B357BD18320DEADFA11","c":12345078,"r":1}
        let token = "tqDOpM5mdNSTCDzyyy6El_Chpj1k-ozzw4AHy-3KJhxkXs8A17GJYVq7CHbgsYMc7n5irdzOJ-IvForV_HiVSnZYpnS_BiORWN6FISVmnwlMxDBIGUqa1XDiBLD7UW8";
        let mt = Service::init("secret", 60);

        let check_result = mt.check(token);

        assert_eq!(Err("Token has expired!".to_owned()), check_result);
    }
}
