use std::str::FromStr;
use std::convert::TryFrom;

use sequoia_openpgp::{self, packet::UserID};
use {Error, Result};

#[derive(Serialize,Deserialize,Clone,Debug,Hash,PartialEq,Eq)]
pub struct Email(String);

impl TryFrom<UserID> for Email {
    type Error = Error;

    fn try_from(uid: UserID) -> Result<Self> {
        let email = String::from_utf8_lossy(uid.userid());

        Self::from_str(&email)
    }
}

impl ToString for Email {
    fn to_string(&self) -> String { self.0.clone() }
}

impl FromStr for Email {
    type Err = Error;

    fn from_str(s: &str) -> Result<Email> {
        let segs = s.split(|c| c == '<' || c == '>').collect::<Vec<_>>();

        if segs.len() == 3 {
            Ok(Email(segs[1].to_string()))
        } else {
            Ok(Email(s.to_string()))
        }
    }
}

#[derive(Serialize,Deserialize,Clone,Debug,Hash,PartialEq,Eq)]
pub struct Fingerprint([u8; 20]);

impl TryFrom<sequoia_openpgp::Fingerprint> for Fingerprint {
    type Error = Error;

    fn try_from(fpr: sequoia_openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            sequoia_openpgp::Fingerprint::Invalid(_) => Err("invalid fingerprint".into()),
        }
    }
}

impl ToString for Fingerprint {
    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0[..]))
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Fingerprint> {
        if !s.starts_with("0x") || s.len() != 40 + 2 {
            return Err(format!("'{}' is not a valid fingerprint", s).into());
        }

        let vec = hex::decode(&s[2..])?;
        if vec.len() == 20 {
            let mut arr = [0u8; 20];

            arr.copy_from_slice(&vec[..]);
            Ok(Fingerprint(arr))
        } else {
            Err(format!("'{}' is not a valid fingerprint", s).into())
        }
    }
}
