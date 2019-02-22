//! Imports keyrings into Hagrids database.
//!
//! Usage:
//!
//!   cargo run --release --example import -- \
//!       <state-dir> <keyring> [<keyring>...]

use std::env;
use std::fs::{create_dir_all, remove_file, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::thread;

extern crate num_cpus;
extern crate pathdiff;
use pathdiff::diff_paths;

extern crate sequoia_openpgp as openpgp;
use openpgp::{Packet, Result};
use openpgp::packet::Tag;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::serialize::{Serialize, SerializeKey};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("Collects statistics about OpenPGP packet dumps.\n\n\
                Usage: {} <state-dir> <keyring> [<keyring>...]\n", args[0]);
    }

    let base = PathBuf::from(&args[1]).join("public");
    if ! base.exists() {
        panic!("{:?} does not exist.  Is {:?} really the state dir?",
               base, args[1]);
    }

    let keyrings = &args[2..];
    let mut threads = Vec::new();
    keyrings.chunks(keyrings.len() / num_cpus::get())
        .for_each(|keyrings| {
            let keyrings: Vec<_> =
                keyrings.iter().map(|k| (*k).clone()).collect();
            let base = base.clone();
            threads.push(thread::spawn(move || {
                do_import(base, keyrings).unwrap();
            }));
        });

    threads.into_iter().for_each(|t| t.join().unwrap());
}

fn do_import(base: PathBuf, keyrings: Vec<String>) -> Result<()> {
    let db = Filesystem::new(base)?;

    // For each input file, create a parser.
    for input in keyrings.iter() {
        eprintln!("Parsing {}...", input);

        let mut acc = Vec::new();
        let mut ppr = PacketParser::from_file(input)?;

        // Iterate over all packets.
        while let PacketParserResult::Some(pp) = ppr {
            // Get the packet and advance the parser.
            let (packet, tmp) = pp.next()?;
            ppr = tmp;

            match packet {
                // If a new TPK starts, parse and import.
                Packet::PublicKey(_) | Packet::SecretKey(_) => {
                    if let Ok(tpk) = openpgp::TPK::from_packet_pile(
                        openpgp::PacketPile::from(
                            ::std::mem::replace(&mut acc, Vec::new())))
                    {
                        db.import(tpk)?;
                    }
                }

                _ => (),
            }

            acc.push(packet);
        }

        if let Ok(tpk) = openpgp::TPK::from_packet_pile(
            openpgp::PacketPile::from(
                ::std::mem::replace(&mut acc, Vec::new())))
        {
            db.import(tpk)?;
        }
    }

    Ok(())
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

pub struct Filesystem {
    base_by_keyid: PathBuf,
    base_by_fingerprint: PathBuf,
}


impl Filesystem {
    pub fn new<P: Into<PathBuf>>(base: P) -> Result<Self> {
        let base = base.into();
        let base_by_keyid = base.join("by-keyid");
        let base_by_fingerprint = base.join("by-fpr");
        Ok(Filesystem {
            base_by_keyid: base_by_keyid,
            base_by_fingerprint: base_by_fingerprint,
        })
    }

    fn import(&self, tpk: openpgp::TPK) -> Result<()> {
        let fingerprint = tpk.primary().fingerprint();
        let tpk_path = self.path_to_fingerprint(&fingerprint);

        let mut sink = File::create(ensure_parent(&tpk_path)?)?;

        // The primary key and related signatures.
        tpk.primary().serialize(&mut sink, Tag::PublicKey)?;
        for s in tpk.selfsigs()          { s.serialize(&mut sink)? }
        for s in tpk.certifications()    { s.serialize(&mut sink)? }
        for s in tpk.self_revocations()  { s.serialize(&mut sink)? }
        for s in tpk.other_revocations() { s.serialize(&mut sink)? }

        // The subkeys and related signatures.
        for skb in tpk.subkeys() {
            skb.subkey().serialize(&mut sink, Tag::PublicSubkey)?;
            for s in skb.selfsigs()          { s.serialize(&mut sink)? }
            for s in skb.certifications()    { s.serialize(&mut sink)? }
            for s in skb.self_revocations()  { s.serialize(&mut sink)? }
            for s in skb.other_revocations() { s.serialize(&mut sink)? }
        }
        drop(sink);

        // Create links.
        self.link_kid(&fingerprint.to_keyid(), &fingerprint)?;
        for skb in tpk.subkeys() {
            let fp = skb.subkey().fingerprint();
            self.link_fpr(&fp, &fingerprint)?;
            self.link_kid(&fp.to_keyid(), &fingerprint)?;
        }

        Ok(())
    }

    /// Returns the path to the given KeyID.
    fn path_to_keyid(&self, keyid: &openpgp::KeyID) -> PathBuf {
        let hex = keyid.to_hex().to_lowercase();
        self.base_by_keyid.join(&hex[..2]).join(&hex[2..])
    }

    /// Returns the path to the given Fingerprint.
    fn path_to_fingerprint(&self, fingerprint: &openpgp::Fingerprint)
                           -> PathBuf {
        let hex = fingerprint.to_hex().to_lowercase();
        self.base_by_fingerprint.join(&hex[..2]).join(&hex[2..])
    }

    fn link_kid(&self, kid: &openpgp::KeyID,
                fpr: &openpgp::Fingerprint) -> Result<()> {
        let link = self.path_to_keyid(kid);
        let target = diff_paths(&self.path_to_fingerprint(fpr),
                                link.parent().unwrap()).unwrap();

        let _ = remove_file(&link);
        symlink(target, ensure_parent(&link)?)?;
        Ok(())
    }

    fn link_fpr(&self, from: &openpgp::Fingerprint,
                fpr: &openpgp::Fingerprint) -> Result<()> {
        if from == fpr {
            return Ok(());
        }
        let link = self.path_to_fingerprint(from);
        let target = diff_paths(&self.path_to_fingerprint(fpr),
                                link.parent().unwrap()).unwrap();

        let _ = remove_file(&link);
        //eprintln!("{:?} -> {:?}", link, target);
        //symlink(&target, ensure_parent(&link)?)?;
        let r = symlink(&target, ensure_parent(&link)?);
        if let Err(e) = r {
            eprintln!("{:?} -> {:?}: {:?}", link, target, e);
        }
        Ok(())
    }
}
