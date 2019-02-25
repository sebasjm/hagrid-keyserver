#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

extern crate failure;
use failure::Error;
use failure::Fallible as Result;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate hex;
extern crate time;
extern crate url;

#[macro_use]
extern crate rocket;
extern crate multipart;
extern crate rocket_contrib;

extern crate sequoia_openpgp;
#[macro_use]
extern crate log;
extern crate base64;
extern crate handlebars;
extern crate lettre;
extern crate lettre_email;
extern crate parking_lot;
extern crate rand;
extern crate structopt;
extern crate tempfile;
extern crate pathdiff;

#[cfg(test)]
extern crate fs_extra;

mod database;
mod mail;
mod types;
mod web;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "hagrid",
    about = "Hagrid - The verifying OpenPGP key server."
)]
pub struct Opt {
    /// More verbose output. Disabled when running as daemon.
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    /// Daemonize after startup.
    #[structopt(short = "d", long = "daemon")]
    daemon: bool,
    /// Base directory
    #[structopt(parse(from_os_str))]
    base: PathBuf,
    /// Port and address to listen on.
    #[structopt(short = "l", long = "listen", default_value = "0.0.0.0:8080")]
    listen: String,
    /// FQDN of the server. Used in templates.
    #[structopt(short = "D", long = "domain", default_value = "localhost")]
    domain: String,
    #[structopt(
        short = "F",
        long = "from",
        default_value = "noreply@localhost"
    )]
    from: String,
}

fn main() {
    use database::{Filesystem, Polymorphic};

    let opt = Opt::from_args();
    println!("{:#?}", opt);

    if !opt.base.is_absolute() {
        panic!("Base directory must be absolute");
    }

    let db = Filesystem::new(opt.base.clone()).unwrap();
    web::serve(&opt, Polymorphic::Filesystem(db)).unwrap();
}
