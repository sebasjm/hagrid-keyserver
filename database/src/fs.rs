use parking_lot::{Mutex, MutexGuard};
use std::convert::{TryInto, TryFrom};
use std::fs::{create_dir_all, read_link, remove_file, rename, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str;

use serde_json;
use tempfile;
use url;
use pathdiff::diff_paths;

//use sequoia_openpgp::armor::{Writer, Kind};

use {Database, Delete, Verify, Query};
use types::{Email, Fingerprint, KeyID};
use Result;

pub struct Filesystem {
    update_lock: Mutex<()>,

    base: PathBuf,
    base_by_keyid: PathBuf,
    base_by_fingerprint: PathBuf,
    base_by_email: PathBuf,
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
    pub fn new<P: Into<PathBuf>>(base: P) -> Result<Self> {
        use std::fs;

        let base: PathBuf = base.into();

        if fs::create_dir(&base).is_err() {
            let meta = fs::metadata(&base);

            match meta {
                Ok(meta) => {
                    if !meta.file_type().is_dir() {
                        return Err(failure::format_err!(
                            "'{}' exists already and is not a directory",
                            base.display()));
                    }

                    if meta.permissions().readonly() {
                        return Err(failure::format_err!(
                            "Cannot write '{}'",
                            base.display()));
                    }
                }

                Err(e) => {
                    return Err(failure::format_err!(
                        "Cannot read '{}': {}",
                        base.display(), e));
                }
            }
        }

        // create directories
        create_dir_all(base.join("verification_tokens"))?;
        create_dir_all(base.join("deletion_tokens"))?;
        create_dir_all(base.join("scratch_pad"))?;

        let base_by_keyid = base.join("public").join("by-keyid");
        let base_by_fingerprint = base.join("public").join("by-fpr");
        let base_by_email = base.join("public").join("by-email");
        create_dir_all(&base_by_keyid)?;
        create_dir_all(&base_by_fingerprint)?;
        create_dir_all(&base_by_email)?;

        info!("Opened base dir '{}'", base.display());
        Ok(Filesystem {
            update_lock: Mutex::new(()),
            base: base,
            base_by_keyid: base_by_keyid,
            base_by_fingerprint: base_by_fingerprint,
            base_by_email: base_by_email,
        })
    }

    /// Returns the path to the given KeyID.
    fn keyid_to_path(&self, keyid: &KeyID) -> PathBuf {
        let hex = keyid.to_string();
        self.base_by_keyid.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Fingerprint.
    fn fingerprint_to_path(&self, fingerprint: &Fingerprint) -> PathBuf {
        let hex = fingerprint.to_string();
        self.base_by_fingerprint.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Email.
    fn email_to_path(&self, email: &Email) -> PathBuf {
        let email =
            url::form_urlencoded::byte_serialize(email.as_str().as_bytes())
                .collect::<String>();
        if email.len() > 2 {
            self.base_by_email.join(&email[..2]).join(&email[2..])
        } else {
            self.base_by_email.join(email)
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

    fn new_token<'a>(&self, base: &'a str) -> Result<(File, String)> {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        let name: String = rng.sample_iter(&Alphanumeric).take(43).collect();
        let dir = self.base.join(base);
        let fd = File::create(dir.join(&name))?;

        Ok((fd, name))
    }

    fn pop_token<'a>(
        &self, base: &'a str, token: &'a str,
    ) -> Result<Box<[u8]>> {
        let path = self.base.join(base).join(token);
        let buf = {
            let mut fd = File::open(&path)?;
            let mut buf = Vec::default();

            fd.read_to_end(&mut buf)?;
            buf.into_boxed_slice()
        };

        remove_file(path)?;
        Ok(buf)
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
        for entry in fs::read_dir(&self.base_by_fingerprint)? {
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
                    _ if typ.is_symlink() =>
                        self.path_to_fingerprint(&path.read_link()?)
                            .ok_or_else(
                                || format_err!("Malformed path: {:?}",
                                              path.read_link().unwrap()))?,
                    _ => return
                        Err(format_err!("{:?} is neither a file nor a symlink \
                                         but a {:?}", path, typ)),
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

                if typ.is_file() {
                    let tpk_primary_fp =
                        tpk.primary().fingerprint().try_into().unwrap();
                    if fp != tpk_primary_fp {
                        return Err(format_err!(
                            "{:?} points to the wrong TPK, expected {} \
                             but found {}",
                            path, fp, tpk_primary_fp));
                    }
                } else {
                    let mut found = false;
                    for skb in tpk.subkeys() {
                        if Fingerprint::try_from(skb.subkey().fingerprint())
                            .unwrap() == fp
                        {
                            found = true;
                            break;
                        }
                    }
                    if ! found {
                        return Err(format_err!(
                            "{:?} points to the wrong TPK, the TPK does not \
                             contain the subkey {}", path, fp));
                    }
                }
            }
        }

        // Check KeyIDs.
        for entry in fs::read_dir(&self.base_by_keyid)? {
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

                let mut found = false;
                for (_, _, key) in tpk.keys() {
                    if KeyID::try_from(key.fingerprint()).unwrap() == id
                    {
                        found = true;
                        break;
                    }
                }
                if ! found {
                    return Err(format_err!(
                        "{:?} points to the wrong TPK, the TPK does not \
                         contain the (sub)key {}", path, id));
                }
            }
        }

        // Check Emails.
        for entry in fs::read_dir(&self.base_by_email)? {
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
        self.update_lock.lock()
    }

    fn new_verify_token(&self, payload: Verify) -> Result<String> {
        let (mut fd, name) = self.new_token("verification_tokens")?;
        fd.write_all(serde_json::to_string(&payload)?.as_bytes())?;

        Ok(name)
    }

    fn new_delete_token(&self, payload: Delete) -> Result<String> {
        let (mut fd, name) = self.new_token("deletion_tokens")?;
        fd.write_all(serde_json::to_string(&payload)?.as_bytes())?;

        Ok(name)
    }

    fn update(
        &self, fpr: &Fingerprint, new: Option<String>,
    ) -> Result<()> {
        let target = self.fingerprint_to_path(fpr);
        let dir = self.base.join("scratch_pad");

        match new {
            Some(new) => {
                let mut tmp = tempfile::Builder::new()
                    .prefix("key")
                    .rand_bytes(16)
                    .tempfile_in(dir)?;

                tmp.write_all(new.as_bytes()).unwrap();
                let _ = tmp.persist(ensure_parent(&target)?)?;

                // fix permissions to 640
                if cfg!(unix) {
                    use std::fs::{set_permissions, Permissions};
                    use std::os::unix::fs::PermissionsExt;

                    let perm = Permissions::from_mode(0o640);
                    set_permissions(target, perm)?;
                }
            }
            None => {
                remove_file(target)?;
            }
        }

        Ok(())
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        use super::Query::*;
        match term {
            ByFingerprint(ref fp) => {
                let path = self.fingerprint_to_path(fp);
                let typ = match path.symlink_metadata() {
                    Ok(meta) => meta.file_type(),
                    Err(_) => return None,
                };

                if typ.is_file() {
                    Some(fp.clone())
                } else if typ.is_symlink() {
                    path.read_link().ok()
                        .and_then(|path| self.path_to_fingerprint(&path))
                } else {
                    // Neither file nor symlink.  Freak value.
                    None
                }
            },
            ByKeyID(ref keyid) => {
                let path = self.keyid_to_path(keyid);
                path.read_link().ok()
                    .and_then(|path| self.path_to_fingerprint(&path))
            },
            ByEmail(ref email) => {
                let path = self.email_to_path(email);
                path.read_link().ok()
                    .and_then(|path| self.path_to_fingerprint(&path))
            },
        }
    }

    /// Gets the path to the underlying file, if any.
    fn lookup_path(&self, term: &Query) -> Option<PathBuf> {
        use super::Query::*;
        let path = match term {
            ByFingerprint(ref fp) => self.fingerprint_to_path(fp),
            ByKeyID(ref keyid) => self.keyid_to_path(keyid),
            ByEmail(ref email) => self.email_to_path(email),
        };

        if path.exists() {
            Some(diff_paths(&path, &self.base).expect("related paths"))
        } else {
            None
        }
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let link = self.email_to_path(&email);
        let target = diff_paths(&self.fingerprint_to_path(fpr),
                                link.parent().unwrap()).unwrap();

        if link == target {
            return Ok(());
        }

        symlink(&target, ensure_parent(&link)?)
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let link = self.email_to_path(&email);

        match read_link(&link) {
            Ok(target) => {
                let expected = diff_paths(&self.fingerprint_to_path(fpr),
                                          link.parent().unwrap()).unwrap();

                if target == expected {
                    remove_file(link)?;
                }
            }
            Err(_) => {}
        }

        Ok(())
    }

    fn link_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        let link = self.keyid_to_path(kid);
        let target = diff_paths(&self.fingerprint_to_path(fpr),
                                link.parent().unwrap()).unwrap();

        if link == target {
            return Ok(());
        }

        if link.exists() {
            match link.symlink_metadata() {
                Ok(ref meta) if meta.file_type().is_file() => {
                    // If a key is a subkey and a primary key, prefer
                    // the primary.
                    return Ok(());
                }
                _ => {}
            }
        }

        symlink(&target, ensure_parent(&link)?)
    }

    fn unlink_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        let link = self.keyid_to_path(kid);

        match read_link(&link) {
            Ok(target) => {
                let expected = self.fingerprint_to_path(fpr);

                if target == expected {
                    remove_file(link)?;
                }
            }
            Err(_) => {}
        }

        Ok(())
    }

    fn link_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        if from == fpr {
            return Ok(());
        }

        let link = self.fingerprint_to_path(from);
        let target = diff_paths(&self.fingerprint_to_path(fpr),
                                link.parent().unwrap()).unwrap();

        symlink(&target, ensure_parent(&link)?)
    }

    fn unlink_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        let link = self.fingerprint_to_path(from);

        match read_link(&link) {
            Ok(target) => {
                let expected = self.fingerprint_to_path(fpr);

                if target == expected {
                    remove_file(link)?;
                }
            }
            Err(_) => {}
        }
        Ok(())
    }

    fn pop_verify_token(&self, token: &str) -> Option<Verify> {
        self.pop_token("verification_tokens", token)
            .ok()
            .and_then(|raw| str::from_utf8(&raw).ok().map(|s| s.to_string()))
            .and_then(|s| {
                let s = serde_json::from_str(&s);
                s.ok()
            })
    }

    fn pop_delete_token(&self, token: &str) -> Option<Delete> {
        self.pop_token("deletion_tokens", token)
            .ok()
            .and_then(|raw| str::from_utf8(&raw).ok().map(|s| s.to_string()))
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    // XXX: slow
    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let target = self.fingerprint_to_path(fpr);

        File::open(target).ok().and_then(|mut fd| {
            let mut buf = String::new();
            if fd.read_to_string(&mut buf).is_ok() {
                Some(buf)
            } else {
                None
            }
        })
    }

    // XXX: slow
    fn by_email(&self, email: &Email) -> Option<String> {
        use std::fs;

        let path = self.email_to_path(&email);

        fs::canonicalize(path)
            .ok()
            .and_then(
                |p| {
                    if p.starts_with(&self.base) {
                        Some(p)
                    } else {
                        None
                    }
                },
            )
            .and_then(|p| File::open(p).ok())
            .and_then(|mut fd| {
                let mut buf = String::new();
                if fd.read_to_string(&mut buf).is_ok() {
                    Some(buf)
                } else {
                    None
                }
            })
    }

    // XXX: slow
    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        use std::fs;

        let path = self.keyid_to_path(kid);

        fs::canonicalize(path)
            .ok()
            .and_then(
                |p| {
                    if p.starts_with(&self.base) {
                        Some(p)
                    } else {
                        None
                    }
                },
            )
            .and_then(|p| File::open(p).ok())
            .and_then(|mut fd| {
                let mut buf = String::new();
                if fd.read_to_string(&mut buf).is_ok() {
                    Some(buf)
                } else {
                    None
                }
            })
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
        let _ = Filesystem::new(tmpdir.path()).unwrap();
    }

    #[test]
    fn new() {
        let tmpdir = TempDir::new().unwrap();
        let db = Filesystem::new(tmpdir.path()).unwrap();
        let k1 = TPKBuilder::default().add_userid("a@invalid.example.org")
            .generate().unwrap().0;
        let k2 = TPKBuilder::default().add_userid("b@invalid.example.org")
            .generate().unwrap().0;
        let k3 = TPKBuilder::default().add_userid("c@invalid.example.org")
            .generate().unwrap().0;

        assert!(db.merge_or_publish(k1).unwrap().len() > 0);
        assert!(db.merge_or_publish(k2.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k2).unwrap().len() > 0);
        assert!(db.merge_or_publish(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k3.clone()).unwrap().len() > 0);
        assert!(!db.merge_or_publish(k3).unwrap().len() > 0);
    }

    #[test]
    fn uid_verification() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_uid_verification(&mut db);
    }

    #[test]
    fn uid_deletion() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_uid_deletion(&mut db);
    }

    #[test]
    fn uid_deletion_request() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_uid_deletion_request(&mut db);
    }


    #[test]
    fn subkey_lookup() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_subkey_lookup(&mut db);
    }

    #[test]
    fn kid_lookup() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_kid_lookup(&mut db);
    }

    #[test]
    fn upload_revoked_tpk() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();
        test::test_upload_revoked_tpk(&mut db);
    }

    #[test]
    fn uid_revocation() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_uid_revocation(&mut db);
    }

    #[test]
    fn key_reupload() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_reupload(&mut db);
    }

    #[test]
    fn uid_replacement() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_uid_replacement(&mut db);
    }

    #[test]
    fn uid_stealing() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_steal_uid(&mut db);
    }

    #[test]
    fn same_email_1() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_same_email_1(&mut db);
    }

    #[test]
    fn same_email_2() {
        let tmpdir = TempDir::new().unwrap();
        let mut db = Filesystem::new(tmpdir.path()).unwrap();

        test::test_same_email_2(&mut db);
    }

    #[test]
    fn reverse_fingerprint_to_path() {
        let tmpdir = TempDir::new().unwrap();
        let db = Filesystem::new(tmpdir.path()).unwrap();

        let fp: Fingerprint =
            "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse().unwrap();

        assert_eq!(db.path_to_fingerprint(&db.fingerprint_to_path(&fp)),
                   Some(fp));
    }
}
