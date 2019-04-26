//! Imports keyrings into Hagrids database.
//!
//! Usage:
//!
//!   cargo run --release --example import -- \
//!       <state-dir> <keyring> [<keyring>...]

#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

use std::env;
use std::path::PathBuf;
use std::thread;
use std::cmp;

extern crate failure;
use failure::Fallible as Result;

extern crate num_cpus;
extern crate tempfile;

extern crate sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};

extern crate hagrid_database as database;
use database::{Database, KeyDatabase};

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
    keyrings.chunks(keyrings.len() / cmp::min(num_cpus::get(), keyrings.len()))
        .for_each(|keyrings| {
            let keyrings: Vec<PathBuf> =
                keyrings.iter().map(|k| (*k).clone().into()).collect();
            let base = base.clone();
            threads.push(thread::spawn(move || {
                do_import(base, keyrings).unwrap();
            }));
        });

    threads.into_iter().for_each(|t| t.join().unwrap());
}

fn do_import(base: PathBuf, keyrings: Vec<PathBuf>) -> Result<()> {
    let db = KeyDatabase::new_from_base(base)?;

    // For each input file, create a parser.
    for input in keyrings.iter() {
        eprintln!("Parsing {:?}...", input);

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
                        db.merge(&tpk)?;
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
            db.merge(&tpk)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod import_tests {
    use std::fs::File;
    use tempfile::tempdir;
    use openpgp::serialize::Serialize;
    use super::*;

    #[test]
    fn import() {
        let root = tempdir().unwrap();

        let db = KeyDatabase::new_from_base(root.path().to_path_buf()).unwrap();

        // Generate a key and import it.
        let (tpk, _) = openpgp::tpk::TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap();
        let import_me = root.path().join("import-me");
        tpk.serialize(&mut File::create(&import_me).unwrap()).unwrap();

        do_import(root.path().to_path_buf(), vec![import_me]).unwrap();

        let check = |query: &str| {
            let tpk_ = db.lookup(&query.parse().unwrap()).unwrap().unwrap();
            assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
            assert_eq!(tpk.subkeys().map(|skb| skb.subkey().fingerprint())
                       .collect::<Vec<_>>(),
                       tpk_.subkeys().map(|skb| skb.subkey().fingerprint())
                       .collect::<Vec<_>>());
            assert_eq!(tpk_.userids().count(), 0);
        };

        check(&format!("{}", tpk.primary().fingerprint()));
        check(&format!("{}", tpk.primary().fingerprint().to_keyid()));
        check(&format!("{}", tpk.subkeys().nth(0).unwrap().subkey()
                       .fingerprint()));
        check(&format!("{}", tpk.subkeys().nth(0).unwrap().subkey()
                       .fingerprint().to_keyid()));
    }
}
