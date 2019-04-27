#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

use std::convert::{TryFrom, TryInto};
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

extern crate failure;
use failure::Error;
use failure::Fallible as Result;
extern crate fs2;
extern crate idna;
#[macro_use] extern crate log;
extern crate parking_lot;
extern crate pathdiff;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tempfile;
extern crate time;
extern crate url;
extern crate hex;

use tempfile::NamedTempFile;

extern crate sequoia_openpgp as openpgp;
use openpgp::{
    TPK,
    tpk::UserIDBinding,
    PacketPile,
    RevocationStatus,
    armor::{Writer, Kind},
    packet::{UserID, Tag},
    parse::Parse,
    serialize::Serialize as OpenPgpSerialize,
};

use serde::{Serialize, Deserialize, Deserializer, Serializer};

pub mod types;
use types::{Email, Fingerprint, KeyID};

pub mod sync;
use sync::MutexGuard;

mod fs;
pub use self::fs::Filesystem as KeyDatabase;

mod stateful_tokens;
pub use stateful_tokens::StatefulTokens;

#[cfg(test)]
mod test;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verify {
    created: i64,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    packets: Vec<u8>,
    fpr: Fingerprint,
    email: Email,
}

fn as_base64<S>(d: &Vec<u8>, serializer: S) -> result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&d))
}

fn from_base64<'de, D>(deserializer: D) -> result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
            base64::decode(&string)
                .map_err(|err| Error::custom(err.to_string()))
        })
}

impl Verify {
    pub fn new(uidb: &UserIDBinding, fpr: Fingerprint) -> Result<Self> {
        use openpgp::serialize::Serialize;

        let mut cur = Cursor::new(Vec::default());
        uidb.userid().serialize(&mut cur)?;

        // Serialize selfsigs and certifications, revocations are
        // never stripped from the TPKs in the first place.
        for s in uidb.selfsigs()          { s.serialize(&mut cur)? }
        for s in uidb.certifications()    { s.serialize(&mut cur)? }

        Ok(Verify {
            created: time::now().to_timespec().sec,
            packets: cur.into_inner(),
            fpr: fpr,
            email: Email::try_from(uidb.userid())?,
        })
    }

    /// Extends the verification token by this userid binding.
    fn extend(&mut self, uidb: &UserIDBinding) -> Result<()> {
        use openpgp::serialize::Serialize;

        uidb.userid().serialize(&mut self.packets)?;

        // Serialize selfsigs and certifications, revocations are
        // never stripped from the TPKs in the first place.
        for s in uidb.selfsigs()          { s.serialize(&mut self.packets)? }
        for s in uidb.certifications()    { s.serialize(&mut self.packets)? }
        Ok(())
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
    /// Lock the DB for a complex update.
    ///
    /// All basic write operations are atomic so we don't need to lock
    /// read operations to ensure that we return something sane.
    fn lock(&self) -> MutexGuard<()>;

    /// Update the data associated with `fpr` with the data in new.
    ///
    /// If new is None, this removes any associated data.
    ///
    /// This function updates the data atomically.  That is, readers
    /// can continue to read from the associated file and they will
    /// either have the old version or the new version, but never an
    /// inconsistent mix or a partial version.
    ///
    /// Note: it is up to the caller to serialize writes.
    fn update(
        &self, fpr: &Fingerprint, new: Option<String>,
    ) -> Result<()>;

    /// Update the TPK associated with `fpr` with the TPK in new.
    ///
    /// If new is None, this removes any associated TPK.
    ///
    /// This function updates the TPK atomically.  That is, readers
    /// can continue to read from the associated file and they will
    /// either have the old version or the new version, but never an
    /// inconsistent mix or a partial version.
    ///
    /// Note: it is up to the caller to serialize writes.
    fn update_tpk(&self, fp: &Fingerprint, new: Option<TPK>) -> Result<()> {
        self.update(fp, if let Some(tpk) = new {
            let mut buf = Vec::new();
            {
                let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey,
                                                   &[][..])?;
                tpk.serialize(&mut armor_writer)?;
            };
            Some(String::from_utf8_lossy(&buf).to_string())
        } else {
            None
        })
    }

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

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_kid(&self, kid: &KeyID) -> Option<String>;
    fn by_email(&self, email: &Email) -> Option<String>;

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

    /// Complex operation that updates a TPK in the database.
    ///
    /// 1. Merge new TPK with old, full TPK
    ///    - if old full TPK == new full TPK, stop
    /// 2. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    /// 3. Write full and published TPK to temporary files
    /// LOCK
    /// 3. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 4. Move full and published temporary TPK to their location
    /// 5. Update all symlinks
    /// UNLOCK
    fn merge(&self, new_tpk: TPK) -> Result<Vec<(Email, String)>> {
        let fpr_primary = Fingerprint::try_from(new_tpk.primary().fingerprint())?;

        let full_tpk_new = if let Some(bytes) = self.by_fpr_full(&fpr_primary) {
            let full_tpk_old = TPK::from_bytes(bytes.as_ref())?;
            let full_tpk_new = new_tpk.merge(full_tpk_old.clone())?;
            // Abort if no changes were made
            // TODO
            // if full_tpk_new == full_tpk_old {
                // return Ok(vec!())
            // }
            full_tpk_new
        } else {
            new_tpk
        };

        let is_revoked = full_tpk_new.revoked(None) != RevocationStatus::NotAsFarAsWeKnow;

        let published_uids: Vec<UserID> = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .map(|tpk| tpk.userids()
                 .map(|binding| binding.userid().clone())
                 .collect()
                ).unwrap_or_default();

        let unpublished_emails = if is_revoked {
            vec!()
        } else {
            let mut unpublished_emails: Vec<(Email, String)> = full_tpk_new
                .userids()
                .filter(|binding| binding.revoked(None) == RevocationStatus::NotAsFarAsWeKnow)
                .map(|binding| binding.userid().clone())
                .filter(|uid| !published_uids.contains(uid))
                .map(|uid| Email::try_from(&uid))
                .flatten()
                .map(|email| {
                    // TODO dup this due to legacy interface
                    let email_str = email.to_string();
                    (email, email_str)
                })
                .collect();
            unpublished_emails.sort();
            unpublished_emails.dedup();
            unpublished_emails
        };

        let revoked_uids: Vec<UserID> = full_tpk_new
            .userids()
            .filter(|binding| binding.revoked(None) != RevocationStatus::NotAsFarAsWeKnow)
            .map(|binding| binding.userid().clone())
            .collect();

        let newly_revoked_uids: Vec<&UserID> = published_uids.iter()
            .filter(|uid| revoked_uids.contains(uid))
            .collect();

        let published_tpk_new = filter_userids(
            &full_tpk_new, |uid| {
                published_uids.contains(uid) && !newly_revoked_uids.contains(&uid)
            })?;

        let newly_revoked_emails: Vec<Email> = published_uids.iter()
            .map(|uid| Email::try_from(uid).ok())
            .flatten()
            .filter(|email| {
                let has_unrevoked_userid = published_tpk_new
                    .userids()
                    .filter(|binding| binding.revoked(None) == RevocationStatus::NotAsFarAsWeKnow)
                    .map(|binding| binding.userid())
                    .map(|uid| Email::try_from(uid).ok())
                    .flatten()
                    .any(|unrevoked_email| unrevoked_email == *email);
                !has_unrevoked_userid
            }).collect();

        let fingerprints = published_tpk_new
            .keys_all()
            .unfiltered()
            .map(|(_, _, key)| key.fingerprint())
            .map(|fpr| Fingerprint::try_from(fpr))
            .flatten();

        let full_tpk_tmp = self.write_to_temp(&tpk_to_string(&full_tpk_new)?)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_new)?)?;

        let _lock = self.lock();

        let fpr_checks = fingerprints
            .map(|fpr| self.check_link_fpr(&fpr, &fpr_primary))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        let fpr_not_linked = fpr_checks.into_iter().flatten();

        // these are very unlikely to fail. but if it happens,
        // database consistency might be compromised!
        self.move_tmp_to_full(full_tpk_tmp, &fpr_primary)?;
        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        for fpr in fpr_not_linked {
            if let Err(e) = self.link_fpr(&fpr, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr, &fpr_primary, e);
            }
            if let Err(e) = self.link_kid(&(&fpr).into(), &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr, &fpr_primary, e);
            }
        }

        for revoked_email in newly_revoked_emails {
            if let Err(e) = self.unlink_email(&revoked_email, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr_primary, &revoked_email, e);
            }
        }

        Ok(unpublished_emails)
    }

    /// Complex operation that publishes some user id for a TPK already in the database.
    ///
    /// 1. Load published TPK
    ///     - if UserID is already in, stop
    /// 2. Load full TPK
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    ///
    /// LOCK
    /// 4. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary TPK to their location
    /// 6. Update all symlinks
    /// UNLOCK
    fn set_verified(&self, fpr_primary: &Fingerprint, email_new: &Email) -> Result<()> {
        let full_tpk = self.by_fpr_full(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let published_uids_old: Vec<UserID> = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .map(|tpk| tpk.userids()
                .map(|binding| binding.userid().clone())
                .collect()
            ).unwrap_or_default();
        let published_emails_old: Vec<Email> = published_uids_old.iter()
            .map(|uid| Email::try_from(uid).ok())
            .flatten()
            .collect();

        // println!("publishing: {:?}", &uid_new);
        if published_emails_old.contains(&email_new) {
            // UserID already published - just stop
            return Ok(());
        }

        let published_tpk_new = {
            filter_userids(&full_tpk,
                |uid| Email::try_from(uid).unwrap() == *email_new || published_uids_old.contains(uid))?
        };

        if ! published_tpk_new
            .userids()
            .map(|binding| binding.userid())
            .any(|uid| Email::try_from(uid).map(|email| email == *email_new).unwrap_or_default()) {
                return Err(failure::err_msg("Requested UserID not found!"));
        }

        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_new)?)?;

        let _lock = self.lock();

        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        if let Err(e) = self.link_email(&email_new, &fpr_primary) {
            info!("Error ensuring email symlink! {} -> {} {:?}",
                  &email_new, &fpr_primary, e);
        }

        Ok(())
    }

    /// Complex operation that un-publishes some user id for a TPK already in the database.
    ///
    /// 1. Load published TPK
    ///     - if UserID is not in, stop
    /// 2. Load full TPK
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    ///
    /// LOCK
    /// 4. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary TPK to their location
    /// 6. Update all symlinks
    /// UNLOCK
    fn set_unverified(&self, fpr_primary: &Fingerprint, email_remove: &Email) -> Result<()> {
        let published_tpk_old = self.by_fpr(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let published_uids_old: Vec<UserID> = published_tpk_old
            .userids()
            .map(|binding| binding.userid().clone())
            .collect();

        println!("unpublishing: {:?}", &email_remove);

        let published_tpk_new = {
            filter_userids(&published_tpk_old,
                |uid| Email::try_from(uid).unwrap() != *email_remove && published_uids_old.contains(uid))?
        };

        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_new)?)?;

        let _lock = self.lock();

        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        if let Err(e) = self.unlink_email(&email_remove, &fpr_primary) {
            info!("Error ensuring email symlink! {} -> {} {:?}",
                  &email_remove, &fpr_primary, e);
        }

        Ok(())
    }

    fn check_link_fpr(&self, fpr: &Fingerprint, target: &Fingerprint) -> Result<Option<Fingerprint>>;

    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String>;

    fn write_to_temp(&self, content: &[u8]) -> Result<NamedTempFile>;
    fn move_tmp_to_full(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;
    fn move_tmp_to_published(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;

    fn merge_or_publish(&self, tpk: &TPK) -> Result<Vec<(Email, String)>> {
        let unpublished_uids = self.merge(tpk.clone())?;

        let fpr_hex = tpk.primary().fingerprint().to_hex();
        let result = unpublished_uids
            .into_iter()
            .map(|(email, uid)| (email, format!("{}|{}", &fpr_hex, uid)))
            .collect();
        Ok(result)
    }

    fn verify_token(
        &self, token_str: &str,
    ) -> Result<Option<(Email, Fingerprint)>> {
        let mut pieces = token_str.splitn(2, "|");
        let fpr: Fingerprint = pieces.next().unwrap().parse().unwrap();
        let email: Email = pieces.next().unwrap().parse().unwrap();
        self.set_verified(&fpr, &email)?;
        Ok(Some((email, fpr)))
    }

    /// Deletes all UserID packets and unlinks all email addresses.
    fn delete_userids(&self, fpr: &Fingerprint) -> Result <()> {
        self.filter_userids(fpr, |_| false)
    }

    /// Deletes all UserID packets matching `addr` (see [RFC2822
    /// name-addr] and unlinks the email addresses.
    ///
    /// [RFC2822 name-addr]: https://tools.ietf.org/html/rfc2822#section-3.4
    fn delete_userids_matching(&self, fpr: &Fingerprint, addr: &Email)
                               -> Result <()> {
        self.set_unverified(fpr, addr)
    }

    /// Deletes all user ids NOT matching fulfilling `filter`.
    ///
    /// I.e. we retain fulfilling `filter`.
    fn filter_userids<F>(&self, fp: &Fingerprint, filter: F) -> Result<()>
        where F: Fn(&UserID) -> bool
    {
        let _ = self.lock();
        match self.lookup(&Query::ByFingerprint(fp.clone()))? {
            Some(tpk) => {
                let mut ok = true;

                // First, we delete the links.
                for uidb in tpk.userids() {
                    if filter(uidb.userid()) {
                        continue;
                    }

                    if let Ok(email) = uidb.userid().try_into() {
                        if let Err(_) =
                            self.unlink_email(&email, fp)
                        {
                            // XXX: We could try to detect failures, and
                            // update the TPK accordingly.
                            ok = false;
                        }
                    }
                }

                // Second, we update the TPK.
                let tpk = filter_userids(&tpk, filter)?;
                self.update_tpk(fp, Some(tpk))?;

                if ok {
                    Ok(())
                } else {
                    Err(failure::err_msg("partial update"))
                }
            },
            None => Ok(()),
        }
    }
}

fn tpk_to_string(tpk: &TPK) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut armor_writer = Writer::new(&mut buf, Kind::PublicKey, &[][..])?;
        tpk.serialize(&mut armor_writer)?;
    }
    Ok(buf)
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
        // Only include userids matching filter
        if filter(uidb.userid()) {
            acc.push(uidb.userid().clone().into());
            for s in uidb.selfsigs()          { acc.push(s.clone().into()) }
            for s in uidb.certifications()    { acc.push(s.clone().into()) }
            for s in uidb.self_revocations()  { acc.push(s.clone().into()) }
            for s in uidb.other_revocations() { acc.push(s.clone().into()) }
        }
    }

    TPK::from_packet_pile(acc.into())
}
