use std::convert::TryFrom;
use std::result;
use std::str::FromStr;

use sequoia_openpgp::{self, packet::UserID};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use {Error, Result};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<UserID> for Email {
    type Error = Error;

    fn try_from(uid: UserID) -> Result<Self> {
        let email = String::from_utf8_lossy(uid.userid());

        Self::from_str(&email)
    }
}

impl ToString for Email {
    fn to_string(&self) -> String {
        self.0.clone()
    }
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Fingerprint([u8; 20]);

impl TryFrom<sequoia_openpgp::Fingerprint> for Fingerprint {
    type Error = Error;

    fn try_from(fpr: sequoia_openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            sequoia_openpgp::Fingerprint::Invalid(_) =>
                Err(failure::err_msg("invalid fingerprint")),
        }
    }
}

impl ToString for Fingerprint {
    fn to_string(&self) -> String {
        hex::encode_upper(&self.0[..])
    }
}

impl Serialize for Fingerprint {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            Self::from_str(&string)
                .map_err(|err| Error::custom(err.to_string()))
        })
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Fingerprint> {
        match sequoia_openpgp::Fingerprint::from_hex(s)? {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            sequoia_openpgp::Fingerprint::Invalid(_) =>
                Err(failure::format_err!("'{}' is not a valid fingerprint", s))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct KeyID([u8; 8]);

impl TryFrom<sequoia_openpgp::Fingerprint> for KeyID {
    type Error = Error;

    fn try_from(fpr: sequoia_openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a).into()),
            sequoia_openpgp::Fingerprint::Invalid(_) => {
                Err(failure::err_msg("invalid fingerprint"))
            }
        }
    }
}

impl From<Fingerprint> for KeyID {
    fn from(fpr: Fingerprint) -> KeyID {
        let mut arr = [0u8; 8];

        arr.copy_from_slice(&fpr.0[12..20]);
        KeyID(arr)
    }
}

impl ToString for KeyID {
    fn to_string(&self) -> String {
        hex::encode_upper(&self.0[..])
    }
}

impl FromStr for KeyID {
    type Err = Error;

    fn from_str(s: &str) -> Result<KeyID> {
        match sequoia_openpgp::KeyID::from_hex(s)? {
            sequoia_openpgp::KeyID::V4(a) => Ok(KeyID(a)),
            sequoia_openpgp::KeyID::Invalid(_) =>
                Err(failure::format_err!("'{}' is not a valid long key ID", s))
        }
    }
}

// impl From<Error> for String {
//     fn from(error: Error) -> Self {
//         format!("{:?}", error)
//     }
// }
