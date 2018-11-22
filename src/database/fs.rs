use std::str;
use std::path::PathBuf;
use std::fs::{File, remove_file, create_dir_all, read_link};
use std::io::{Write, Read};
use std::os::unix::fs::symlink;

use tempfile;
use serde_json;
use url;

use database::{Verify, Delete, Database};
use Result;
use types::{Email, Fingerprint};

pub struct Filesystem {
    base: PathBuf,
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
                        return Err(format!("'{}' exists already and is not a directory",
                                           base.display()).into());
                    }

                    if meta.permissions().readonly() {
                        return Err(format!("Cannot write '{}'", base.display()).into());
                    }
                }

                Err(e) => {
                    return Err(format!("Cannot read '{}': {}", base.display(),e).into());
                }
            }
        }

        // create directories
        create_dir_all(base.join("verification_tokens"))?;
        create_dir_all(base.join("deletion_tokens"))?;
        create_dir_all(base.join("scratch_pad"))?;
        create_dir_all(base.join("public").join("by-fpr"))?;
        create_dir_all(base.join("public").join("by-email"))?;

        info!("Opened base dir '{}'", base.display());
        Ok(Filesystem{
            base: base,
        })
    }

    fn new_token<'a>(&self, base: &'a str) -> Result<(File, String)> {
        use rand::{thread_rng, Rng};
        use rand::distributions::Alphanumeric;

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        let name: String = rng.sample_iter(&Alphanumeric).take(43).collect();
        let dir = self.base.join(base);
        let fd = File::create(dir.join(name.clone()))?;

        Ok((fd, name))
    }

    fn pop_token<'a>(&self, base: &'a str, token: &'a str) -> Result<Box<[u8]>> {
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

    fn compare_and_swap(&self, fpr: &Fingerprint, old: Option<&[u8]>, new: Option<&[u8]>) -> Result<bool> {
        let target = self.base.join("public").join("by-fpr").join(fpr.to_string());
        let dir = self.base.join("scratch_pad");

        match new {
            Some(new) => {
                let mut tmp = tempfile::Builder::new()
                    .prefix("key")
                    .rand_bytes(16)
                    .tempfile_in(dir)?;
                tmp.write_all(new)?;

                if target.is_file() {
                    if old.is_some() { remove_file(target.clone())?; }
                    else { return Err(format!("stray file {}", target.display()).into()); }
                }
                let _ = tmp.persist(target)?;

                Ok(true)
            }
            None => {
                remove_file(target)?;
                Ok(true)
            }
        }
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) {
        let email = url::form_urlencoded::byte_serialize(email.to_string().as_bytes()).collect::<String>();
        let target = self.base.join("public").join("by-fpr").join(fpr.to_string());
        let link = self.base.join("public").join("by-email").join(email);

        if link.exists() {
            let _ = remove_file(link.clone());
        }

        let _ = symlink(target, link);
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) {
        let email = url::form_urlencoded::byte_serialize(email.to_string().as_bytes()).collect::<String>();
        let link = self.base.join("public").join("by-email").join(email);

        match read_link(link.clone()) {
            Ok(target) => {
                let expected = self.base.join("public").join("by-fpr").join(fpr.to_string());

                if target == expected {
                    let _ = remove_file(link);
                }
            }
            Err(_) => {}
        }
    }

    fn pop_verify_token(&self, token: &str) -> Option<Verify> {
        self.pop_token("verification_tokens", token).ok().and_then(|raw| {
            str::from_utf8(&raw).ok().map(|s| s.to_string())
        }).and_then(|s| {
            let s = serde_json::from_str(&s);
            s.ok()
        })
    }

    fn pop_delete_token(&self, token: &str) -> Option<Delete> {
        self.pop_token("deletion_tokens", token).ok().and_then(|raw| {
            str::from_utf8(&raw).ok().map(|s| s.to_string())
        }).and_then(|s| {
            serde_json::from_str(&s).ok()
        })
    }

    // XXX: slow
    fn by_fpr(&self, fpr: &Fingerprint) -> Option<Box<[u8]>> {
        let target = self.base.join("public").join("by-fpr").join(fpr.to_string());

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

        let email = url::form_urlencoded::byte_serialize(email.to_string().as_bytes()).collect::<String>();
        let path = self.base.join("public").join("by-email").join(email);

        fs::canonicalize(path).ok()
            .and_then(|p| {
                if p.starts_with(&self.base) {
                    Some(p)
                } else {
                    None
                }
            }).and_then(|p| {
                File::open(p).ok()
            }).and_then(|mut fd| {
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
    use tempfile::TempDir;
    use openpgp::tpk::TPKBuilder;
    use database::test;

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
}
