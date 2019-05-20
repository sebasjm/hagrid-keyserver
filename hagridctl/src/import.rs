//! Imports keyrings into Hagrids database.
//!
//! Usage:
//!
//!   cargo run --release --example import -- \
//!       <state-dir> <keyring> [<keyring>...]

use std::path::{Path,PathBuf};
use std::fs::File;
use std::io::Read;

extern crate failure;
use failure::Fallible as Result;

extern crate tempfile;

extern crate sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};

extern crate hagrid_database as database;
use database::{Database, KeyDatabase, ImportResult};

use indicatif::{ProgressBar,ProgressStyle};

use HagridConfig;

pub fn do_import(config: &HagridConfig, keyrings: Vec<PathBuf>) -> Result<()> {
    let db = KeyDatabase::new(
        config.keys_internal_dir.as_ref().unwrap(),
        config.keys_external_dir.as_ref().unwrap(),
        config.tmp_dir.as_ref().unwrap()
    )?;

    // For each input file, create a parser.
    for input in keyrings.iter() {
        eprintln!("Parsing {:?}...", input);
        let errors = import_from_file(&db, &input)?;
        for error in errors {
            eprintln!("{}", error);
        }
    }

    Ok(())
}

struct ImportStats {
    progress: ProgressBar,
    count_total: u64,
    count_err: u64,
    count_new: u64,
    count_updated: u64,
    count_unchanged: u64,
    errors: Vec<failure::Error>,
}

impl ImportStats {
    fn new(progress: ProgressBar) -> Self {
        ImportStats {
            progress,
            count_total: 0,
            count_err: 0,
            count_new: 0,
            count_updated: 0,
            count_unchanged: 0,
            errors: vec!(),
        }
    }

    fn update(&mut self, result: Result<ImportResult>) {
        // If a new TPK starts, parse and import.
        self.count_total += 1;
        match result {
            Err(x) => {
                self.count_err += 1;
                self.errors.push(x);
            },
            Ok(ImportResult::New(_)) => self.count_new += 1,
            Ok(ImportResult::Updated(_)) => self.count_updated += 1,
            Ok(ImportResult::Unchanged(_)) => self.count_unchanged += 1,
        }
        self.progress_update();
    }

    fn progress_update(&self) {
        if (self.count_total % 10) != 0 {
            return;
        }
        self.progress.set_message(&format!(
                "imported {:5} keys, {:4} New {:4} Updated {:4} Unchanged {:4} Errors",
                self.count_total, self.count_new, self.count_updated, self.count_unchanged, self.count_err));

    }
    fn progress_finish(&self) {
        self.progress.finish_with_message(&format!(
                "imported {:5} keys, {:4} New {:4} Updated {:4} Unchanged {:4} Errors",
                self.count_total, self.count_new, self.count_updated, self.count_unchanged, self.count_err));

    }
}

fn import_from_file(db: &KeyDatabase, input: &Path) -> Result<Vec<failure::Error>> {
    let input_file = File::open(input)?;
    let pb = ProgressBar::new(input_file.metadata()?.len());
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
        .progress_chars("##-"));
    let input_reader = &mut pb.wrap_read(input_file);
    let mut stats = ImportStats::new(pb);

    read_file_to_tpks(input_reader, &mut |acc| {
        let result = import_key(&db, acc);
        stats.update(result);
    })?;

    stats.progress_finish();
    Ok(stats.errors)
}

fn read_file_to_tpks(
    reader: impl Read,
    callback: &mut impl FnMut(Vec<Packet>) -> ()
) -> Result<()> {
    let mut ppr = PacketParser::from_reader(reader)?;
    let mut acc = Vec::new();

    // Iterate over all packets.
    while let PacketParserResult::Some(pp) = ppr {
        // Get the packet and advance the parser.
        let (packet, tmp) = pp.next()?;
        ppr = tmp;

        if !acc.is_empty() {
            if let Packet::PublicKey(_) | Packet::SecretKey(_) = packet {
                callback(acc);
                acc = vec!();
            }
        }

        acc.push(packet);
    }

    Ok(())
}

fn import_key(db: &KeyDatabase, packets: Vec<Packet>) -> Result<ImportResult> {
    let packet_pile = openpgp::PacketPile::from(packets);
    openpgp::TPK::from_packet_pile(packet_pile)
        .and_then(|tpk| {
            db.merge(tpk)
        })
}

/*
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
*/
