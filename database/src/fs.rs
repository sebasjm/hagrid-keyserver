use std::convert::{TryInto, TryFrom};
use std::fs::{create_dir_all, read_link, remove_file, rename};
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile;
use url;
use pathdiff::diff_paths;

//use sequoia_openpgp::armor::{Writer, Kind};

use {Database, Query};
use types::{Email, Fingerprint, KeyID};
use sync::{MutexGuard, FlockMutex};
use Result;

use tempfile::NamedTempFile;

pub struct Filesystem {
    update_lock: FlockMutex,

    tmp_dir: PathBuf,

    keys_dir: PathBuf,
    keys_dir_full: PathBuf,
    keys_dir_published: PathBuf,

    links_dir_by_fingerprint: PathBuf,
    links_dir_by_keyid: PathBuf,
    links_dir_by_email: PathBuf,
}

/// Returns the given path, ensuring that the parent directory exists.
///
/// Use this on paths returned by .path_to_* before creating the
/// object.
fn ensure_parent(path: &Path) -> Result<&Path> {
    let parent = path.parent().unwrap();
    create_dir_all(parent)?;
    Ok(path)
}


impl Filesystem {
    pub fn new_from_base(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir: PathBuf = base_dir.into();

        let keys_dir = base_dir.join("keys");
        let tmp_dir = base_dir.join("tmp");

        Self::new(keys_dir, tmp_dir)
    }

    pub fn new(
        keys_dir: impl Into<PathBuf>,
        tmp_dir: impl Into<PathBuf>,
    ) -> Result<Self> {

        /*
         use std::fs;
         if fs::create_dir(&state_dir).is_err() {
            let meta = fs::metadata(&state_dir);

            match meta {
                Ok(meta) => {
                    if !meta.file_type().is_dir() {
                        return Err(failure::format_err!(
                            "'{}' exists already and is not a directory",
                            state_dir.display()));
                    }

                    if meta.permissions().readonly() {
                        return Err(failure::format_err!(
                            "Cannot write '{}'",
                            state_dir.display()));
                    }
                }

                Err(e) => {
                    return Err(failure::format_err!(
                        "Cannot read '{}': {}",
                        state_dir.display(), e));
                }
            }
        }*/

        let tmp_dir = tmp_dir.into();
        create_dir_all(&tmp_dir)?;

        let keys_dir: PathBuf = keys_dir.into();
        let keys_dir_full = keys_dir.join("full");
        let keys_dir_published = keys_dir.join("published");
        create_dir_all(&keys_dir_full)?;
        create_dir_all(&keys_dir_published)?;

        let links_dir_by_keyid = keys_dir.join("by-keyid");
        let links_dir_by_fingerprint = keys_dir.join("by-fpr");
        let links_dir_by_email = keys_dir.join("by-email");
        create_dir_all(&links_dir_by_keyid)?;
        create_dir_all(&links_dir_by_fingerprint)?;
        create_dir_all(&links_dir_by_email)?;

        info!("Opened filesystem database.");
        info!("keys_dir: '{}'", keys_dir.display());
        info!("tmp_dir: '{}'", tmp_dir.display());
        Ok(Filesystem {
            update_lock: FlockMutex::new(&keys_dir)?,
            keys_dir,
            tmp_dir,

            keys_dir_full,
            keys_dir_published,

            links_dir_by_keyid,
            links_dir_by_fingerprint,
            links_dir_by_email,
        })
    }

    /// Returns the path to the given Fingerprint.
    fn fingerprint_to_path_full(&self, fingerprint: &Fingerprint) -> PathBuf {
        let hex = fingerprint.to_string();
        self.keys_dir_full.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Fingerprint.
    fn fingerprint_to_path_published(&self, fingerprint: &Fingerprint) -> PathBuf {
        let hex = fingerprint.to_string();
        self.keys_dir_published.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given KeyID.
    fn link_by_keyid(&self, keyid: &KeyID) -> PathBuf {
        let hex = keyid.to_string();
        self.links_dir_by_keyid.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Fingerprint.
    fn link_by_fingerprint(&self, fingerprint: &Fingerprint) -> PathBuf {
        let hex = fingerprint.to_string();
        self.links_dir_by_fingerprint.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Email.
    fn link_by_email(&self, email: &Email) -> PathBuf {
        let email =
            url::form_urlencoded::byte_serialize(email.as_str().as_bytes())
                .collect::<String>();
        if email.len() > 2 {
            self.links_dir_by_email.join(&email[..2]).join(&email[2..])
        } else {
            self.links_dir_by_email.join(email)
        }
    }

    fn read_from_path(&self, path: &Path) -> Option<String> {
        use std::fs;

        if !path.starts_with(&self.keys_dir) {
            panic!("Attempted to access file outside keys_dir!");
        }

        if path.exists() {
            fs::read_to_string(path).ok()
        } else {
            None
        }
    }

    /// Returns the KeyID the given path is pointing to.
    fn path_to_keyid(&self, path: &Path) -> Option<KeyID> {
        use std::str::FromStr;
        let rest = path.file_name()?;
        let prefix = path.parent()?.file_name()?;
        KeyID::from_str(&format!("{}{}", prefix.to_str()?, rest.to_str()?))
            .ok()
    }

    /// Returns the Fingerprint the given path is pointing to.
    fn path_to_fingerprint(&self, path: &Path) -> Option<Fingerprint> {
        use std::str::FromStr;
        let rest = path.file_name()?;
        let prefix = path.parent()?.file_name()?;
        Fingerprint::from_str(&format!("{}{}", prefix.to_str()?, rest.to_str()?))
            .ok()
    }

    /// Returns the Fingerprint the given path is pointing to.
    ///
    /// This function must be used when converting links connecting
    /// subkey fingerprints to the TPK.
    ///
    /// Here, a complication arises if both fingerprints share the
    /// same two nibble prefix, because they end up in the same
    /// subdirectory.
    fn path_to_fingerprint_base(&self, base: &Path, path: &Path)
                                -> Option<Fingerprint> {
        use std::str::FromStr;

        let rest = path.file_name()?;
        let prefix =
            if path.to_str().unwrap().len() == 38 {
                base.file_name()?
            } else {
                path.parent().unwrap().file_name()?
            };

        Fingerprint::from_str(&format!("{}{}", prefix.to_str()?, rest.to_str()?))
            .ok()
    }


    /// Returns the Email the given path is pointing to.
    fn path_to_email(&self, path: &Path) -> Option<Email> {
        use std::str::FromStr;
        let rest = path.file_name()?;
        let prefix = path.parent()?.file_name()?;
        let joined = format!("{}{}", prefix.to_str()?, rest.to_str()?);
        let decoded = url::form_urlencoded::parse(joined.as_bytes())
            .next()?.0;
        Email::from_str(&decoded).ok()
    }

    /// Checks the database for consistency.
    ///
    /// Note that this operation may take a long time, and is
    /// generally only useful for testing.
    pub fn check_consistency(&self) -> Result<()> {
        use std::fs;
        use std::collections::HashMap;
        use failure::format_err;

        // A cache of all TPKs, for quick lookups.
        let mut tpks = HashMap::new();

        // Check Fingerprints.
        for entry in fs::read_dir(&self.keys_dir_published)? {
            let prefix = entry?;
            let prefix_path = prefix.path();
            if ! prefix_path.is_dir() {
                return Err(format_err!("{:?} is not a directory", prefix_path));
            }

            for entry in fs::read_dir(prefix_path)? {
                let entry = entry?;
                let path = entry.path();
                let typ = fs::symlink_metadata(&path)?.file_type();

                // The Fingerprint corresponding with this path.
                let fp = self.path_to_fingerprint(&path)
                    .ok_or_else(|| format_err!("Malformed path: {:?}", path))?;

                // Compute the corresponding primary fingerprint just
                // by looking at the paths.
                let primary_fp = match () {
                    _ if typ.is_file() =>
                        fp.clone(),
                    _ => return
                        Err(format_err!("{:?} is not a file but a {:?}", path, typ)),
                };

                // Load into cache.
                if ! tpks.contains_key(&primary_fp) {
                    tpks.insert(
                        primary_fp.clone(),
                        self.lookup(&Query::ByFingerprint(primary_fp.clone()))
                            ?.ok_or_else(
                                || format_err!("No TPK with fingerprint {:?}",
                                               primary_fp))?);
                }
                let tpk = tpks.get(&primary_fp).unwrap();

                let tpk_primary_fp =
                    tpk.primary().fingerprint().try_into().unwrap();
                if fp != tpk_primary_fp {
                    return Err(format_err!(
                        "{:?} points to the wrong TPK, expected {} \
                            but found {}",
                        path, fp, tpk_primary_fp));
                }
            }
        }

        // Check subkeys
        for entry in fs::read_dir(&self.links_dir_by_fingerprint)? {
            let prefix = entry?;
            let prefix_path = prefix.path();
            if ! prefix_path.is_dir() {
                return Err(format_err!("{:?} is not a directory", prefix_path));
            }

            for entry in fs::read_dir(prefix_path)? {
                let entry = entry?;
                let path = entry.path();
                let typ = fs::symlink_metadata(&path)?.file_type();

                // The KeyID corresponding with this path.
                let fp = self.path_to_fingerprint(&path)
                    .ok_or_else(|| format_err!("Malformed path: {:?}", path))?;

                // Compute the corresponding primary fingerprint just
                // by looking at the paths.
                let primary_fp = match () {
                    _ if typ.is_symlink() =>
                        self.path_to_fingerprint(&path.read_link()?)
                            .ok_or_else(
                                || format_err!("Malformed path: {:?}",
                                              path.read_link().unwrap()))?,
                    _ => return
                        Err(format_err!("{:?} is not a symlink but a {:?}",
                                        path, typ)),
                };

                let tpk = tpks.get(&primary_fp)
                    .ok_or_else(
                        || format_err!("Broken symlink {:?}: No such Key {}",
                                       path, primary_fp))?;

                let found = tpk.keys_all()
                    .map(|(_, _, key)| Fingerprint::try_from(key.fingerprint()).unwrap())
                    .any(|key_fp| key_fp == fp);
                if ! found {
                    return Err(format_err!(
                        "{:?} points to the wrong TPK, the TPK does not \
                            contain the subkey {}", path, fp));
                }
            }
        }

        // Check KeyIDs.
        for entry in fs::read_dir(&self.links_dir_by_keyid)? {
            let prefix = entry?;
            let prefix_path = prefix.path();
            if ! prefix_path.is_dir() {
                return Err(format_err!("{:?} is not a directory", prefix_path));
            }

            for entry in fs::read_dir(prefix_path)? {
                let entry = entry?;
                let path = entry.path();
                let typ = fs::symlink_metadata(&path)?.file_type();

                // The KeyID corresponding with this path.
                let id = self.path_to_keyid(&path)
                    .ok_or_else(|| format_err!("Malformed path: {:?}", path))?;

                // Compute the corresponding primary fingerprint just
                // by looking at the paths.
                let primary_fp = match () {
                    _ if typ.is_symlink() =>
                        self.path_to_fingerprint(&path.read_link()?)
                            .ok_or_else(
                                || format_err!("Malformed path: {:?}",
                                              path.read_link().unwrap()))?,
                    _ => return
                        Err(format_err!("{:?} is not a symlink but a {:?}",
                                        path, typ)),
                };

                let tpk = tpks.get(&primary_fp)
                    .ok_or_else(
                        || format_err!("Broken symlink {:?}: No such Key {}",
                                       path, primary_fp))?;

                let found = tpk.keys_all()
                    .map(|(_, _, key)| KeyID::try_from(key.fingerprint()).unwrap())
                    .any(|key_fp| key_fp == id);
                if ! found {
                    return Err(format_err!(
                        "{:?} points to the wrong TPK, the TPK does not \
                         contain the (sub)key {}", path, id));
                }
            }
        }

        // Check Emails.
        for entry in fs::read_dir(&self.links_dir_by_email)? {
            let prefix = entry?;
            let prefix_path = prefix.path();
            if ! prefix_path.is_dir() {
                return Err(format_err!("{:?} is not a directory", prefix_path));
            }

            for entry in fs::read_dir(prefix_path)? {
                let entry = entry?;
                let path = entry.path();
                let typ = fs::symlink_metadata(&path)?.file_type();

                // The Email corresponding with this path.
                let email = self.path_to_email(&path)
                    .ok_or_else(|| format_err!("Malformed path: {:?}", path))?;

                // Compute the corresponding primary fingerprint just
                // by looking at the paths.
                let primary_fp = match () {
                    _ if typ.is_symlink() =>
                        self.path_to_fingerprint(&path.read_link()?)
                            .ok_or_else(
                                || format_err!("Malformed path: {:?}",
                                              path.read_link().unwrap()))?,
                    _ => return
                        Err(format_err!("{:?} is not a symlink but a {:?}",
                                        path, typ)),
                };

                let tpk = tpks.get(&primary_fp)
                    .ok_or_else(
                        || format_err!("Broken symlink {:?}: No such Key {}",
                                       path, primary_fp))?;

                let mut found = false;
                for uidb in tpk.userids() {
                    if Email::try_from(uidb.userid()).unwrap() == email
                    {
                        found = true;
                        break;
                    }
                }
                if ! found {
                    return Err(format_err!(
                        "{:?} points to the wrong TPK, the TPK does not \
                         contain the email {}", path, email));
                }
            }
        }

        Ok(())
    }
}

// Like `symlink`, but instead of failing if `symlink_name` already
// exists, atomically update `symlink_name` to have `symlink_content`.
fn symlink(symlink_content: &Path, symlink_name: &Path) -> Result<()> {
    use std::os::unix::fs::{symlink};

    let symlink_dir = ensure_parent(symlink_name)?.parent().unwrap();
    let tmp_dir = tempfile::Builder::new()
        .prefix("link")
        .rand_bytes(16)
        .tempdir_in(symlink_dir)?;
    let symlink_name_tmp = tmp_dir.path().join("link");

    symlink(&symlink_content, &symlink_name_tmp)?;
    rename(&symlink_name_tmp, &symlink_name)?;
    Ok(())
}

impl Database for Filesystem {
    fn lock(&self) -> MutexGuard<()> {
        self.update_lock.lock().into()
    }

    fn write_to_temp(&self, content: &[u8]) -> Result<NamedTempFile> {
        let mut tempfile = tempfile::Builder::new()
            .prefix("key")
            .rand_bytes(16)
            .tempfile_in(&self.tmp_dir)?;

        tempfile.write_all(content).unwrap();

        // fix permissions to 640
        if cfg!(unix) {
            use std::fs::{set_permissions, Permissions};
            use std::os::unix::fs::PermissionsExt;

            let perm = Permissions::from_mode(0o640);
            set_permissions(tempfile.path(), perm)?;
        }

        Ok(tempfile)
    }
    fn move_tmp_to_full(&self, file: NamedTempFile, fpr: &Fingerprint) -> Result<()> {
        let target = self.fingerprint_to_path_full(fpr);
        file.persist(ensure_parent(&target)?)?;
        Ok(())
    }
    fn move_tmp_to_published(&self, file: NamedTempFile, fpr: &Fingerprint) -> Result<()> {
        let target = self.fingerprint_to_path_published(fpr);
        file.persist(ensure_parent(&target)?)?;
        Ok(())
    }

    fn check_link_fpr(&self, fpr: &Fingerprint, fpr_target: &Fingerprint) -> Result<Option<Fingerprint>> {
        let link = self.link_by_fingerprint(&fpr);
        let target = diff_paths(&self.fingerprint_to_path_published(fpr_target),
                                link.parent().unwrap()).unwrap();

        if link == target {
            return Ok(None);
        }

        Ok(Some(fpr.clone()))
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        use super::Query::*;
        match term {
            ByFingerprint(ref fp) => {
                let path = self.link_by_fingerprint(fp);
                let typ = match path.symlink_metadata() {
                    Ok(meta) => meta.file_type(),
                    Err(_) => return None,
                };

                if typ.is_file() {
                    Some(fp.clone())
                } else if typ.is_symlink() {
                    path.read_link().ok()
                        .and_then(|link_path|
                                  self.path_to_fingerprint_base(
                                      path.parent().unwrap(), &link_path))
                } else {
                    // Neither file nor symlink.  Freak value.
                    None
                }
            },
            ByKeyID(ref keyid) => {
                let path = self.link_by_keyid(keyid);
                path.read_link().ok()
                    .and_then(|path| self.path_to_fingerprint(&path))
            },
            ByEmail(ref email) => {
                let path = self.link_by_email(email);
                path.read_link().ok()
                    .and_then(|path| self.path_to_fingerprint(&path))
            },
        }
    }

    /// Gets the path to the underlying file, if any.
    fn lookup_path(&self, term: &Query) -> Option<PathBuf> {
        use super::Query::*;
        let path = match term {
            ByFingerprint(ref fp) => self.link_by_fingerprint(fp),
            ByKeyID(ref keyid) => self.link_by_keyid(keyid),
            ByEmail(ref email) => self.link_by_email(email),
        };

        if path.exists() {
            let x = diff_paths(&path, &self.keys_dir).expect("related paths");
            Some(x)
        } else {
            None
        }
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let link = self.link_by_email(&email);
        let target = diff_paths(&self.fingerprint_to_path_published(fpr),
                                link.parent().unwrap()).unwrap();

        if link == target {
            return Ok(());
        }

        symlink(&target, ensure_parent(&link)?)
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let link = self.link_by_email(&email);

        match read_link(&link) {
            Ok(target) => {
                let expected = diff_paths(&self.fingerprint_to_path_published(fpr),
                                          link.parent().unwrap()).unwrap();

                if target == expected {
                    remove_file(link)?;
                }
            }
            Err(_) => {}
        }

        Ok(())
    }

    fn link_fpr(&self, from: &Fingerprint, primary_fpr: &Fingerprint) -> Result<()> {
        let link_fpr = self.link_by_fingerprint(from);
        let link_keyid = self.link_by_keyid(&from.into());
        let target = diff_paths(&self.fingerprint_to_path_published(primary_fpr),
                                link_fpr.parent().unwrap()).unwrap();

        symlink(&target, ensure_parent(&link_fpr)?)?;
        symlink(&target, ensure_parent(&link_keyid)?)
    }

    fn unlink_fpr(&self, from: &Fingerprint, primary_fpr: &Fingerprint) -> Result<()> {
        let link_fpr = self.link_by_fingerprint(from);
        let link_keyid = self.link_by_keyid(&from.into());
        let expected = self.fingerprint_to_path_published(primary_fpr);

        match read_link(&link_fpr) {
            Ok(target) => {
                if target == expected {
                    remove_file(link_fpr)?;
                }
            }
            Err(_) => {}
        }
        match read_link(&link_keyid) {
            Ok(target) => {
                if target == expected {
                    remove_file(link_keyid)?;
                }
            }
            Err(_) => {}
        }

        Ok(())
    }

    // XXX: slow
    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String> {
        let path = self.fingerprint_to_path_full(fpr);
        self.read_from_path(&path)
    }

    // XXX: slow
    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let path = self.link_by_fingerprint(fpr);
        self.read_from_path(&path)
    }

    // XXX: slow
    fn by_email(&self, email: &Email) -> Option<String> {
        let path = self.link_by_email(&email);
        self.read_from_path(&path)
    }

    // XXX: slow
    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        let path = self.link_by_keyid(kid);
        self.read_from_path(&path)
    }
}

#[cfg(test)]
impl Drop for Filesystem {
    fn drop(&mut self) {
        self.check_consistency().expect("inconsistent database");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test;
    use openpgp::tpk::TPKBuilder;
    use tempfile::TempDir;

    #[test]
    fn init() {
        let tmpdir = TempDir::new().unwrap();
        let _ = Filesystem::new_from_base(tmpdir.path()).unwrap();
    }

    #[test]
    fn new() {
        let tmpdir = TempDir::new().unwrap();
        let db = Filesystem::new_from_base(tmpdir.path()).unwrap();
        let k1 = TPKBuilder::default().add_userid("a@invalid.example.org")
            .generate().unwrap().0;
        let k2 = TPKBuilder::default().add_userid("b@invalid.example.org")
            .generate().unwrap().0;
        let k3 = TPKBuilder::default().add_userid("c@invalid.example.org")
            .generate().unwrap().0;

        assert!(db.merge(k1).unwrap().len() > 0);
        assert!(db.merge(k2.clone()).unwrap().len() > 0);
        assert!(!db.merge(k2).unwrap().len() > 0);
        assert!(db.merge(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge(k3).unwrap().len() > 0);
    }

    #[test]
    fn uid_verification() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_uid_verification(&mut db);
    }

    #[test]
    fn uid_deletion() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_uid_deletion(&mut db);
    }

    #[test]
    fn subkey_lookup() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_subkey_lookup(&mut db);
    }

    #[test]
    fn kid_lookup() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_kid_lookup(&mut db);
    }

    #[test]
    fn upload_revoked_tpk() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();
        test::test_upload_revoked_tpk(&mut db);
    }

    #[test]
    fn uid_revocation() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_uid_revocation(&mut db);
    }

    #[test]
    fn key_reupload() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_reupload(&mut db);
    }

    #[test]
    fn uid_replacement() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_uid_replacement(&mut db);
    }

    #[test]
    fn uid_unlinking() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();
        test::test_unlink_uid(&mut db);
    }

    #[test]
    fn same_email_1() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_same_email_1(&mut db);
    }

    #[test]
    fn same_email_2() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        test::test_same_email_2(&mut db);
    }

    #[test]
    fn reverse_fingerprint_to_path() {
        let tmpdir = TempDir::new().unwrap();
        let db = Filesystem::new_from_base(tmpdir.path()).unwrap();

        let fp: Fingerprint =
            "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse().unwrap();

        assert_eq!(db.path_to_fingerprint(&db.link_by_fingerprint(&fp)),
                   Some(fp.clone()));

        // Special case: Relative symlink to a fingerprint with the
        // same two nibble prefix.
        assert_eq!(
            db.path_to_fingerprint_base(
                &db.links_dir_by_fingerprint.join("CB"),
                &PathBuf::from("CD8F030588653EEDD7E2659B7DD433F254904A")),
            Some(fp));
    }
}
