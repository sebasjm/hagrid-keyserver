use std::convert::TryFrom;
use std::io::Cursor;
use std::result;

use sequoia_openpgp::{
    constants::SignatureType, packet::Signature, packet::UserID, parse::Parse,
    Packet, TPK,
};
use serde::{Deserialize, Deserializer, Serializer};
use time;
use types::{Email, Fingerprint, KeyID};
use Result;

mod fs;
pub use self::fs::Filesystem;
mod memory;
pub use self::memory::Memory;
mod poly;
pub use self::poly::Polymorphic;

#[cfg(test)]
mod test;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verify {
    created: i64,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    packets: Box<[u8]>,
    fpr: Fingerprint,
    email: Email,
}

fn as_base64<S>(d: &Box<[u8]>, serializer: S) -> result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&d))
}

fn from_base64<'de, D>(deserializer: D) -> result::Result<Box<[u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
            base64::decode(&string)
                .map_err(|err| Error::custom(err.to_string()))
        })
        .map(|bytes| bytes.into_boxed_slice())
}

impl Verify {
    pub fn new(
        uid: &UserID, sig: &[Signature], fpr: Fingerprint,
    ) -> Result<Self> {
        use sequoia_openpgp::serialize::Serialize;

        let mut cur = Cursor::new(Vec::default());
        let res: Result<()> = uid
            .serialize(&mut cur)
            .map_err(|e| format!("sequoia_openpgp: {}", e).into());
        res?;

        for s in sig {
            let res: Result<()> = s
                .serialize(&mut cur)
                .map_err(|e| format!("sequoia_openpgp: {}", e).into());
            res?;
        }

        Ok(Verify {
            created: time::now().to_timespec().sec,
            packets: cur.into_inner().into(),
            fpr: fpr,
            email: Email::try_from(uid.clone())?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Delete {
    created: i64,
    fpr: Fingerprint,
}

impl Delete {
    pub fn new(fpr: Fingerprint) -> Self {
        Delete { created: time::now().to_timespec().sec, fpr: fpr }
    }
}

pub trait Database: Sync + Send {
    fn new_verify_token(&self, payload: Verify) -> Result<String>;
    fn new_delete_token(&self, payload: Delete) -> Result<String>;

    // Update the data associated with `fpr` with the data in new.
    //
    // If new is None, this removes any associated data.
    //
    // This function updates the data atomically.  That is, readers
    // can continue to read from the associated file and they will
    // either have the old version or the new version, but never an
    // inconsistent mix or a partial version.
    //
    // Note: it is up to the caller to serialize writes.
    fn update(
        &self, fpr: &Fingerprint, new: Option<&[u8]>,
    ) -> Result<()>;

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;
    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;

    fn link_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()>;
    fn unlink_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()>;

    fn link_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;
    fn unlink_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;

    // (verified uid, fpr)
    fn pop_verify_token(&self, token: &str) -> Option<Verify>;
    // fpr
    fn pop_delete_token(&self, token: &str) -> Option<Delete>;

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>>;
    fn by_kid(&self, kid: &KeyID) -> Option<Box<[u8]>>;
    fn by_email(&self, email: &Email) -> Option<Box<[u8]>>;

    fn strip_userids(tpk: TPK) -> Result<TPK> {
        let pile = tpk
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    &Packet::PublicKey(_) | &Packet::PublicSubkey(_) => true,
                    &Packet::Signature(ref sig) => {
                        sig.sigtype() == SignatureType::DirectKey
                            || sig.sigtype() == SignatureType::SubkeyBinding
                    }
                    _ => false,
                }
            })
            .collect::<Vec<_>>();

        TPK::from_packet_pile(pile.into())
            .map_err(|e| format!("openpgp: {}", e).into())
    }

    fn tpk_into_bytes(tpk: &TPK) -> Result<Vec<u8>> {
        use sequoia_openpgp::serialize::Serialize;
        use std::io::Cursor;

        let mut cur = Cursor::new(Vec::default());
        tpk.serialize(&mut cur)
            .map(|_| cur.into_inner())
            .map_err(|e| format!("{}", e).into())
    }

    fn link_subkeys(
        &self, fpr: &Fingerprint, subkeys: Vec<sequoia_openpgp::Fingerprint>,
    ) -> Result<()> {
        // link (subkey) kid & and subkey fpr
        self.link_kid(&fpr.clone().into(), &fpr)?;

        for sub_fpr in subkeys {
            let sub_fpr = Fingerprint::try_from(sub_fpr)?;

            self.link_kid(&sub_fpr.clone().into(), &fpr)?;
            self.link_fpr(&sub_fpr, &fpr)?;
        }

        Ok(())
    }

    fn unlink_userids(&self, fpr: &Fingerprint, userids: Vec<Email>)
                      -> Result<()> {
        for uid in userids {
            self.unlink_email(&uid, fpr)?;
        }
        Ok(())
    }

    fn merge_or_publish(&self, mut tpk: TPK) -> Result<Vec<(Email, String)>> {
        use sequoia_openpgp::RevocationStatus;

        let fpr = Fingerprint::try_from(tpk.primary().fingerprint())?;
        let mut all_uids = Vec::default();
        let mut active_uids = Vec::default();
        let mut verified_uids = Vec::default();

        // update verify tokens
        for uid in tpk.userids() {
            let email = Email::try_from(uid.userid().clone())?;

            match uid.revoked(None) {
                RevocationStatus::CouldBe(_) | RevocationStatus::Revoked(_) => {
                    match self.by_email(&email) {
                        None => {}
                        Some(other_tpk) => {
                            match TPK::from_bytes(&other_tpk) {
                                Ok(other_tpk) => {
                                    all_uids
                                        .push((email, other_tpk.fingerprint()));
                                }
                                Err(_) => {}
                            }
                        }
                    };
                }
                RevocationStatus::NotAsFarAsWeKnow => {
                    let add_to_verified = match self.by_email(&email) {
                        None => false,
                        Some(other_tpk) => {
                            match TPK::from_bytes(&other_tpk) {
                                Ok(other_tpk) => {
                                    all_uids.push((
                                        email.clone(),
                                        other_tpk.fingerprint(),
                                    ));
                                    other_tpk.fingerprint() == tpk.fingerprint()
                                }
                                Err(_) => false,
                            }
                        }
                    };

                    if add_to_verified {
                        verified_uids.push(email.clone());
                    } else {
                        let payload = Verify::new(
                            uid.userid(),
                            uid.selfsigs(),
                            fpr.clone(),
                        )?;

                        active_uids.push((
                            email.clone(),
                            self.new_verify_token(payload)?,
                        ));
                    }
                }
            }
        }

        let subkeys =
            tpk.subkeys().map(|s| s.subkey().fingerprint()).collect::<Vec<_>>();

        tpk = Self::strip_userids(tpk)?;

        for (email, fpr) in all_uids {
            self.unlink_email(&email, &Fingerprint::try_from(fpr).unwrap())?;
        }

        // merge or update key db
        let data = match self.by_fpr(&fpr).map(|x| x.to_vec()) {
            Some(old) => {
                let new = TPK::from_bytes(&old).unwrap();
                let tpk = new.merge(tpk.clone()).unwrap();
                Self::tpk_into_bytes(&tpk)?
            }

            None => {
                Self::tpk_into_bytes(&tpk)?
            }
        };

        self.update(&fpr, Some(&data))?;

        self.link_subkeys(&fpr, subkeys)?;
        for email in verified_uids {
            self.link_email(&email, &fpr)?;
        }

        Ok(active_uids)
    }

    // if (uid, fpr) = pop-token(tok) {
    //  while cas-failed() {
    //    tpk = by_fpr(fpr)
    //    merged = add-uid(tpk, uid)
    //    cas(tpk, merged)
    //  }
    // }
    fn verify_token(
        &self, token: &str,
    ) -> Result<Option<(Email, Fingerprint)>> {
        match self.pop_verify_token(token) {
            Some(Verify { created, packets, fpr, email }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 {
                    return Ok(None);
                }

                match self.by_fpr(&fpr).map(|x| x.to_vec()) {
                    Some(old) => {
                        let mut new = old.clone();
                        new.extend(packets.into_iter());

                        self.update(&fpr, Some(&new))?;
                        self.link_email(&email, &fpr)?;
                        return Ok(Some((email.clone(), fpr.clone())));
                    }

                    None => {
                        return Ok(None);
                    }
                }
            }
            None => Err("No such token".into()),
        }
    }

    fn request_deletion(
        &self, fpr: Fingerprint,
    ) -> Result<(String, Vec<Email>)> {
        match self.by_fpr(&fpr) {
            Some(tpk) => {
                let payload = Delete::new(fpr);
                let tok = self.new_delete_token(payload)?;
                let tpk = match TPK::from_bytes(&tpk) {
                    Ok(tpk) => tpk,
                    Err(e) => {
                        return Err(
                            format!("Failed to parse TPK: {:?}", e).into()
                        );
                    }
                };
                let emails = tpk
                    .userids()
                    .filter_map(|uid| {
                        Email::try_from(uid.userid().clone()).ok()
                    })
                    .collect::<Vec<_>>();

                Ok((tok, emails))
            }

            None => Err("Unknown key".into()),
        }
    }

    // if fpr = pop-token(tok) {
    //  tpk = by_fpr(fpr)
    //  for uid in tpk.userids {
    //    del-uid(uid)
    //  }
    //  del-fpr(fpr)
    // }
    fn confirm_deletion(&self, token: &str) -> Result<bool> {
        match self.pop_delete_token(token) {
            Some(Delete { created, fpr }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 {
                    return Ok(false);
                }

                loop {
                    match self.by_fpr(&fpr).map(|x| x.to_vec()) {
                        Some(old) => {
                            let tpk = match TPK::from_bytes(&old) {
                                Ok(tpk) => tpk,
                                Err(e) => {
                                    return Err(format!(
                                        "Failed to parse old TPK: {:?}",
                                        e
                                    )
                                    .into());
                                }
                            };

                            for uid in tpk.userids() {
                                self.unlink_email(
                                    &Email::try_from(uid.userid().clone())?,
                                    &fpr,
                                )?;
                            }

                            self.update(&fpr, None)?;
                            return Ok(true);
                        }
                        None => {
                            return Ok(false);
                        }
                    }
                }
            }

            None => Ok(false),
        }
    }
}
