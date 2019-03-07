use std::convert::TryFrom;
use std::result;
use std::str::FromStr;

use openpgp::packet::UserID;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use {Error, Result};

/// Holds a normalized email address.
///
/// Email addresses should be normalized as follows:
///
///  - Convert to UTF-8 and ignore user ids that are not valid UTF-8
///  - Do puny code normalization
///  - Lower-case the whole thing using the empty locale
///
/// See https://autocrypt.org/level1.html#e-mail-address-canonicalization
#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&UserID> for Email {
    type Error = Error;

    fn try_from(uid: &UserID) -> Result<Self> {
        Self::from_str(&String::from_utf8(uid.userid().into())?)
    }
}

impl ToString for Email {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// Placeholder parser.
///
/// See https://gitlab.com/sequoia-pgp/hagrid/issues/58
fn parse2822address(s: &str) -> Result<(&str, &str)> {
    let segs = s.split(|c| c == '<' || c == '>').collect::<Vec<_>>();
    let addr = match segs.len() {
        3 => segs[1],
        1 => s,
        _ => return Err(failure::err_msg("malformed")),
    };

    match addr.split(|c| c == '@').collect::<Vec<_>>() {
        ref parts if parts.len() == 2 =>
            Ok((parts[0], parts[1])),
        _ => Err(failure::err_msg("malformed")),
    }
}

impl FromStr for Email {
    type Err = Error;

    fn from_str(s: &str) -> Result<Email> {
        let (localpart, domain) = parse2822address(s)?;

        // Normalize Unicode in domains.
        let domain = idna::domain_to_ascii(domain)
            .map_err(|e| failure::format_err!(
                "punycode conversion failed: {:?}", e))?;

        // Join.
        let address = format!("{}@{}", localpart, domain);

        // Convert to lowercase without tailoring, i.e. without taking
        // any locale into account.  See:
        //
        //  - https://www.w3.org/International/wiki/Case_folding
        //  - https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
        //  - http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G33992
        let address = address.to_lowercase();

        Ok(Email(address))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email() {
        let c = |s| Email::from_str(s).unwrap();
        assert_eq!(c("foo@example.org").as_str(), "foo@example.org");
        assert_eq!(c("<foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(c("Foo <foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(c("Foo Bar <foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(c("\"Foo Bar\" <foo@example.org>").as_str(),
                   "foo@example.org");
        assert_eq!(c("foo@👍.example.org").as_str(),
                   "foo@xn--yp8h.example.org");
        assert_eq!(c("Foo@example.org").as_str(), "foo@example.org");
        assert_eq!(c("foo@EXAMPLE.ORG").as_str(), "foo@example.org");
    }
}
