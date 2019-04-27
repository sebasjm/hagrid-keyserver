#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

use std::convert::TryFrom;
use std::io::Cursor;
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
    fn merge(&self, new_tpk: TPK) -> Result<Vec<Email>> {
        let fpr_primary = Fingerprint::try_from(new_tpk.primary().fingerprint())?;

        let full_tpk_old = self.by_fpr_full(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok());
        let (full_tpk_new, full_tpk_unchanged) = if let Some(full_tpk_old) = full_tpk_old {
            let full_tpk_new = new_tpk.merge(full_tpk_old.clone())?;
            let full_tpk_unchanged = full_tpk_new == full_tpk_old;
            (full_tpk_new, full_tpk_unchanged)
        } else {
            (new_tpk, false)
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
            let mut unpublished_emails: Vec<Email> = full_tpk_new
                .userids()
                .filter(|binding| binding.revoked(None) == RevocationStatus::NotAsFarAsWeKnow)
                .map(|binding| binding.userid().clone())
                .filter(|uid| !published_uids.contains(uid))
                .map(|uid| Email::try_from(&uid))
                .flatten()
                .collect();
            unpublished_emails.sort();
            unpublished_emails.dedup();
            unpublished_emails
        };

        // Abort if no changes were made
        if full_tpk_unchanged {
            println!("tpk unchanged!");
            return Ok(unpublished_emails);
        }

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
    fn set_email_published(&self, fpr_primary: &Fingerprint, email_new: &Email) -> Result<()> {
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
    fn set_email_unpublished_filter(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: impl Fn(&UserID) -> bool,
    ) -> Result<()> {
        let published_tpk_old = self.by_fpr(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let published_emails_old: Vec<Email> = published_tpk_old
            .userids()
            .map(|binding| binding.userid())
            .map(|uid| Email::try_from(uid))
            .flatten()
            .collect();

        let published_tpk_new = {
            filter_userids(&published_tpk_old, |uid| email_remove(uid))?
        };

        let published_emails_new: Vec<Email> = published_tpk_new
            .userids()
            .map(|binding| binding.userid())
            .map(|uid| Email::try_from(uid))
            .flatten()
            .collect();

        let unpublished_emails = published_emails_old
            .iter()
            .filter(|email| !published_emails_new.contains(email));

        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_new)?)?;

        let _lock = self.lock();

        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        for unpublished_email in unpublished_emails {
            if let Err(e) = self.unlink_email(&unpublished_email, &fpr_primary) {
                info!("Error ensuring email symlink! {} -> {} {:?}",
                    &unpublished_email, &fpr_primary, e);
            }
        }

        Ok(())
    }

    fn set_email_unpublished(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: &Email,
    ) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary,
            |uid| Email::try_from(uid).unwrap() != *email_remove
        )
    }

    fn set_email_unpublished_all(
        &self,
        fpr_primary: &Fingerprint,
    ) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary, |_| false)
    }

    fn check_link_fpr(&self, fpr: &Fingerprint, target: &Fingerprint) -> Result<Option<Fingerprint>>;

    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String>;

    fn write_to_temp(&self, content: &[u8]) -> Result<NamedTempFile>;
    fn move_tmp_to_full(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;
    fn move_tmp_to_published(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;
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
