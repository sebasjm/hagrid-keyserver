#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

use std::convert::TryFrom;
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

extern crate failure;
use failure::Error;
use failure::Fallible as Result;
extern crate idna;
#[macro_use] extern crate log;
extern crate parking_lot;
use parking_lot::MutexGuard;
extern crate pathdiff;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tempfile;
extern crate time;
extern crate url;
extern crate hex;

extern crate sequoia_openpgp as openpgp;
use openpgp::{
    Packet, TPK,
    PacketPile,
    armor::{Writer, Kind},
    constants::SignatureType, packet::Signature, packet::UserID, parse::Parse,
    packet::Tag,
    serialize::Serialize as OpenPgpSerialize,
};

use serde::{Serialize, Deserialize, Deserializer, Serializer};

pub mod types;
use types::{Email, Fingerprint, KeyID};

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
        use openpgp::serialize::Serialize;

        let mut cur = Cursor::new(Vec::default());
        uid.serialize(&mut cur)?;

        for s in sig {
            s.serialize(&mut cur)?;
        }

        Ok(Verify {
            created: time::now().to_timespec().sec,
            packets: cur.into_inner().into(),
            fpr: fpr,
            email: Email::try_from(uid)?,
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

/// Represents a search query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    ByFingerprint(Fingerprint),
    ByKeyID(KeyID),
    ByEmail(Email),
}

impl FromStr for Query {
    type Err = failure::Error;

    fn from_str(term: &str) -> Result<Self> {
        use self::Query::*;

        if let Ok(fp) = Fingerprint::from_str(term) {
            Ok(ByFingerprint(fp))
        } else if let Ok(keyid) = KeyID::from_str(term) {
            Ok(ByKeyID(keyid))
        } else if let Ok(email) = Email::from_str(term) {
            Ok(ByEmail(email))
        } else {
            Err(failure::err_msg("Malformed query"))
        }
    }
}

pub trait Database: Sync + Send {
    // Lock the DB for a complex update.
    //
    // All basic write operations are atomic so we don't need to lock
    // read operations to ensure that we return something sane.
    fn lock(&self) -> MutexGuard<()>;

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
        &self, fpr: &Fingerprint, new: Option<String>,
    ) -> Result<()>;

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address.
    fn lookup(&self, term: &Query) -> Result<Option<TPK>> {
        use self::Query::*;
        let armored = match term {
            ByFingerprint(ref fp) => self.by_fpr(fp),
            ByKeyID(ref keyid) => self.by_kid(keyid),
            ByEmail(ref email) => self.by_email(&email),
        };

        match armored {
            Some(armored) => Ok(Some(TPK::from_bytes(armored.as_bytes())?)),
            None => Ok(None),
        }
    }

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address, returning the primary fingerprint.
    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint>;

    /// Gets the path to the underlying file, if any.
    fn lookup_path(&self, term: &Query) -> Option<PathBuf> {
        let _ = term;
        None
    }

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

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_kid(&self, kid: &KeyID) -> Option<String>;
    fn by_email(&self, email: &Email) -> Option<String>;

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

        Ok(TPK::from_packet_pile(pile.into())?)
    }

    fn tpk_into_bytes(tpk: &TPK) -> Result<Vec<u8>> {
        use openpgp::serialize::Serialize;
        use std::io::Cursor;

        let mut cur = Cursor::new(Vec::default());
        tpk.serialize(&mut cur)
            .map(|_| cur.into_inner())
    }

    fn link_subkeys(
        &self, fpr: &Fingerprint, subkeys: Vec<sequoia_openpgp::Fingerprint>,
    ) -> Result<()> {
        let _ = self.lock();

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
        let _ = self.lock();

        for uid in userids {
            self.unlink_email(&uid, fpr)?;
        }
        Ok(())
    }

    /// Merges the given TPK into the database.
    ///
    /// If the TPK is in the database, it is merged with the given
    /// one.  Fingerprint and KeyID links are created.  No new UserID
    /// links are created.
    ///
    /// UserIDs that are already present in the database will receive
    /// new certificates.
    fn merge(&self, new_tpk: TPK) -> Result<()> {
        let fpr = Fingerprint::try_from(new_tpk.primary().fingerprint())?;
        let _ = self.lock();

        // See if the TPK is in the database.
        let old_tpk = if let Some(bytes) = self.by_fpr(&fpr) {
            Some(TPK::from_bytes(bytes.as_ref())?)
        } else {
            None
        };

        // If we already know some UserIDs, we want to keep any
        // updates that come in.
        use std::collections::HashSet;
        let mut known_uids = HashSet::new();
        if let Some(old_tpk) = old_tpk.as_ref() {
            for uidb in old_tpk.userids() {
                known_uids.insert(uidb.userid().clone());
            }
        }
        let new_tpk = filter_userids(&new_tpk, move |u| known_uids.contains(u))?;

        // Maybe merge.
        let tpk = if let Some(old_tpk) = old_tpk {
            old_tpk.merge(new_tpk)?
        } else {
            new_tpk
        };

        let mut buf = Vec::new();
        {
            let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey,
                                               &[][..])?;
            tpk.serialize(&mut armor_writer)?;
        };
        let armored = String::from_utf8_lossy(&buf);
        self.update(&fpr, Some(armored.into_owned()))?;
        self.link_subkeys(&fpr,
                          tpk.subkeys().map(|s| s.subkey().fingerprint())
                          .collect())?;
        Ok(())
    }

    fn merge_or_publish(&self, mut tpk: TPK) -> Result<Vec<(Email, String)>> {
        use openpgp::RevocationStatus;

        let fpr = Fingerprint::try_from(tpk.primary().fingerprint())?;
        let mut all_uids = Vec::default();
        let mut active_uids = Vec::default();
        let mut verified_uids = Vec::default();

        let _ = self.lock();

        // update verify tokens
        for uid in tpk.userids() {
            let email = if let Ok(m) = Email::try_from(uid.userid()) {
                m
            } else {
                // Ignore non-UTF8 userids.
                continue;
            };

            match uid.revoked(None) {
                RevocationStatus::CouldBe(_) | RevocationStatus::Revoked(_) => {
                    match self.by_email(&email) {
                        None => {}
                        Some(other_tpk) => {
                            match TPK::from_bytes(other_tpk.as_bytes()) {
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
                            match TPK::from_bytes(other_tpk.as_bytes()) {
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
        let data = match self.by_fpr(&fpr) {
            Some(old) => {
                let new = TPK::from_bytes(old.as_bytes()).unwrap();
                let tpk = new.merge(tpk.clone()).unwrap();
                Self::tpk_into_bytes(&tpk)?
            }

            None => {
                Self::tpk_into_bytes(&tpk)?
            }
        };

        let mut buf = std::io::Cursor::new(vec![]);
        {
            let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey,
                                               &[][..])?;

            armor_writer.write_all(&data)?;
        };
        let armored = String::from_utf8_lossy(buf.get_ref());


        self.update(&fpr, Some(armored.into_owned()))?;

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
        let _ = self.lock();

        match self.pop_verify_token(token) {
            Some(Verify { created, packets, fpr, email }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 {
                    return Ok(None);
                }

                match self.by_fpr(&fpr) {
                    Some(old) => {

                        let tpk = TPK::from_bytes(old.as_bytes()).unwrap();
                        let packet_pile = PacketPile::from_bytes(&packets)
                            .unwrap().into_children().collect::<Vec<_>>();
                        let new = tpk.merge_packets(packet_pile).unwrap();


                        let mut buf = std::io::Cursor::new(vec![]);
                        {
                            let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey,
                                                               &[][..])?;

                            armor_writer.write_all(&Self::tpk_into_bytes(&new).unwrap())?;
                        };
                        let armored = String::from_utf8_lossy(buf.get_ref());

                        self.update(&fpr, Some(armored.into_owned()))?;
                        self.link_email(&email, &fpr)?;
                        return Ok(Some((email.clone(), fpr.clone())));
                    }

                    None => {
                        return Ok(None);
                    }
                }
            }
            None => Err(failure::err_msg("No such token")),
        }
    }

    fn request_deletion(
        &self, fpr: Fingerprint,
    ) -> Result<(String, Vec<Email>)> {
        let _ = self.lock();

        match self.by_fpr(&fpr) {
            Some(tpk) => {
                let payload = Delete::new(fpr);
                let tok = self.new_delete_token(payload)?;
                let tpk = match TPK::from_bytes(tpk.as_bytes()) {
                    Ok(tpk) => tpk,
                    Err(e) => {
                        return Err(
                            failure::format_err!("Failed to parse TPK: {:?}", e)
                        );
                    }
                };
                let emails = tpk
                    .userids()
                    .filter_map(|uid| {
                        Email::try_from(uid.userid()).ok()
                    })
                    .collect::<Vec<_>>();

                Ok((tok, emails))
            }

            None => Err(failure::err_msg("Unknown key")),
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
        let _ = self.lock();

        match self.pop_delete_token(token) {
            Some(Delete { created, fpr }) => {
                let now = time::now().to_timespec().sec;
                if created > now || now - created > 3 * 3600 {
                    return Ok(false);
                }

                loop {
                    match self.by_fpr(&fpr) {
                        Some(old) => {
                            let tpk = match TPK::from_bytes(old.as_bytes()) {
                                Ok(tpk) => tpk,
                                Err(e) => {
                                    return Err(failure::format_err!(
                                        "Failed to parse old TPK: {:?}",
                                        e));
                                }
                            };

                            for uid in tpk.userids() {
                                self.unlink_email(
                                    &Email::try_from(uid.userid())?,
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

/// Filters the TPK, keeping only those UserIDs that fulfill the
/// predicate `filter`.
fn filter_userids<F>(tpk: &TPK, filter: F) -> Result<TPK>
    where F: Fn(&UserID) -> bool
{
    // Iterate over the TPK, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    acc.push(tpk.primary().clone().into_packet(Tag::PublicKey)?);
    for s in tpk.selfsigs()          { acc.push(s.clone().into()) }
    for s in tpk.certifications()    { acc.push(s.clone().into()) }
    for s in tpk.self_revocations()  { acc.push(s.clone().into()) }
    for s in tpk.other_revocations() { acc.push(s.clone().into()) }

    // The subkeys and related signatures.
    for skb in tpk.subkeys() {
        acc.push(skb.subkey().clone().into_packet(Tag::PublicSubkey)?);
        for s in skb.selfsigs()          { acc.push(s.clone().into()) }
        for s in skb.certifications()    { acc.push(s.clone().into()) }
        for s in skb.self_revocations()  { acc.push(s.clone().into()) }
        for s in skb.other_revocations() { acc.push(s.clone().into()) }
    }

    // Updates for UserIDs fulfilling `filter`.
    for uidb in tpk.userids() {
        if ! filter(uidb.userid()) {
            continue;
        }

        acc.push(uidb.userid().clone().into());
        for s in uidb.selfsigs()          { acc.push(s.clone().into()) }
        for s in uidb.certifications()    { acc.push(s.clone().into()) }
        for s in uidb.self_revocations()  { acc.push(s.clone().into()) }
        for s in uidb.other_revocations() { acc.push(s.clone().into()) }
    }

    TPK::from_packet_pile(acc.into())
}
