use std::fs::{create_dir_all, read_link, remove_file, File};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::str;

use serde_json;
use tempfile;
use url;
use pathdiff::diff_paths;

use database::{Database, Delete, Verify};
use types::{Email, Fingerprint, KeyID};
use Result;

pub struct Filesystem {
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
                        return Err(format!(
                            "'{}' exists already and is not a directory",
                            base.display()
                        )
                        .into());
                    }

                    if meta.permissions().readonly() {
                        return Err(format!(
                            "Cannot write '{}'",
                            base.display()
                        )
                        .into());
                    }
                }

                Err(e) => {
                    return Err(format!(
                        "Cannot read '{}': {}",
                        base.display(),
                        e
                    )
                    .into());
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
            base: base,
            base_by_keyid: base_by_keyid,
            base_by_fingerprint: base_by_fingerprint,
            base_by_email: base_by_email,
        })
    }

    /// Returns the path to the given KeyID.
    fn path_to_keyid(&self, keyid: &KeyID) -> PathBuf {
        let hex = keyid.to_string();
        self.base_by_keyid.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Fingerprint.
    fn path_to_fingerprint(&self, fingerprint: &Fingerprint) -> PathBuf {
        let hex = fingerprint.to_string();
        self.base_by_fingerprint.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Email.
    fn path_to_email(&self, email: &str) -> PathBuf {
        if email.len() > 2 {
            self.base_by_email.join(&email[..2]).join(&email[2..])
        } else {
            self.base_by_email.join(email)
        }
    }

    fn new_token<'a>(&self, base: &'a str) -> Result<(File, String)> {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        let name: String = rng.sample_iter(&Alphanumeric).take(43).collect();
        let dir = self.base.join(base);
        let fd = File::create(dir.join(name.clone()))?;

        Ok((fd, name))
    }

    fn pop_token<'a>(
        &self, base: &'a str, token: &'a str,
    ) -> Result<Box<[u8]>> {
        let path = self.base.join(base).join(token);
        let buf = {
            let mut fd = File::open(path.clone())?;
            let mut buf = Vec::default();

            fd.read_to_end(&mut buf)?;
            buf.into_boxed_slice()
        };

        remove_file(path)?;
        Ok(buf)
    }
}

impl Database for Filesystem {
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
        &self, fpr: &Fingerprint, new: Option<&[u8]>,
    ) -> Result<()> {
        let target = self.path_to_fingerprint(fpr);
        let dir = self.base.join("scratch_pad");

        match new {
            Some(new) => {
                let mut tmp = tempfile::Builder::new()
                    .prefix("key")
                    .rand_bytes(16)
                    .tempfile_in(dir)?;
                tmp.write_all(new)?;

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

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let email =
            url::form_urlencoded::byte_serialize(email.to_string().as_bytes())
                .collect::<String>();
        let link = self.path_to_email(&email);
        let target = diff_paths(&self.path_to_fingerprint(fpr),
                                link.parent().unwrap()).unwrap();

        if link.exists() {
            match link.symlink_metadata() {
                Ok(ref meta) if meta.file_type().is_symlink() => {
                    remove_file(link.clone())?;
                }
                _ => {}
            }
        }

        symlink(target, ensure_parent(&link)?)?;
        Ok(())
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let email =
            url::form_urlencoded::byte_serialize(email.to_string().as_bytes())
                .collect::<String>();
        let link = self.path_to_email(&email);

        match read_link(link.clone()) {
            Ok(target) => {
                let expected = diff_paths(&self.path_to_fingerprint(fpr),
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
        let link = self.path_to_keyid(kid);
        let target = diff_paths(&self.path_to_fingerprint(fpr),
                                link.parent().unwrap()).unwrap();

        if link.exists() {
            match link.symlink_metadata() {
                Ok(ref meta) if meta.file_type().is_symlink() => {
                    remove_file(link.clone())?;
                }
                _ => {}
            }
        }

        symlink(target, ensure_parent(&link)?)?;
        Ok(())
    }

    fn unlink_kid(&self, kid: &KeyID, fpr: &Fingerprint) -> Result<()> {
        let link = self.path_to_keyid(kid);

        match read_link(link.clone()) {
            Ok(target) => {
                let expected = self.path_to_fingerprint(fpr);

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

        let link = self.path_to_fingerprint(from);
        let target = diff_paths(&self.path_to_fingerprint(fpr),
                                link.parent().unwrap()).unwrap();

        if link.exists() {
            match link.symlink_metadata() {
                Ok(ref meta) if meta.file_type().is_symlink() => {
                    remove_file(link.clone())?;
                }
                _ => {}
            }
        }

        symlink(target, ensure_parent(&link)?)?;
        Ok(())
    }

    fn unlink_fpr(&self, from: &Fingerprint, fpr: &Fingerprint) -> Result<()> {
        let link = self.path_to_fingerprint(from);

        match read_link(link.clone()) {
            Ok(target) => {
                let expected = self.path_to_fingerprint(fpr);

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
    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>> {
        let target = self.path_to_fingerprint(fpr);

        File::open(target).ok().and_then(|mut fd| {
            let mut buf = Vec::default();
            if fd.read_to_end(&mut buf).is_ok() {
                Some(buf.into_boxed_slice())
            } else {
                None
            }
        })
    }

    // XXX: slow
    fn by_email(&self, email: &Email) -> Option<Box<[u8]>> {
        use std::fs;

        let email =
            url::form_urlencoded::byte_serialize(email.to_string().as_bytes())
                .collect::<String>();
        let path = self.path_to_email(&email);

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
                let mut buf = Vec::default();
                if fd.read_to_end(&mut buf).is_ok() {
                    Some(buf.into_boxed_slice())
                } else {
                    None
                }
            })
    }

    // XXX: slow
    fn by_kid(&self, kid: &KeyID) -> Option<Box<[u8]>> {
        use std::fs;

        let path = self.path_to_keyid(kid);

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
                let mut buf = Vec::default();
                if fd.read_to_end(&mut buf).is_ok() {
                    Some(buf.into_boxed_slice())
                } else {
                    None
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database::test;
    use sequoia_openpgp::tpk::TPKBuilder;
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
        let k1 = TPKBuilder::default().add_userid("a").generate().unwrap().0;
        let k2 = TPKBuilder::default().add_userid("b").generate().unwrap().0;
        let k3 = TPKBuilder::default().add_userid("c").generate().unwrap().0;

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
}
