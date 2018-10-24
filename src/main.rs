#![feature(plugin, decl_macro, custom_derive)]
#![plugin(rocket_codegen)]
#![recursion_limit = "1024"]
#![feature(try_from)]

extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

extern crate time;
extern crate url;
extern crate hex;

#[cfg(not(test))] extern crate rocket;
#[cfg(test)] extern crate rocket;
extern crate rocket_contrib;
extern crate multipart;

extern crate openpgp;
#[macro_use] extern crate error_chain;
#[macro_use] extern crate log;
extern crate rand;
extern crate tempfile;
extern crate parking_lot;
extern crate structopt;

mod web;
mod database;
mod types;

mod errors {
    error_chain!{
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
            Json(::serde_json::Error);
            Persist(::tempfile::PersistError);
            RktConfig(::rocket::config::ConfigError);
            StringUtf8Error(::std::string::FromUtf8Error);
            StrUtf8Error(::std::str::Utf8Error);
            HexError(::hex::FromHexError);
        }
    }
}
use errors::*;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "garbage", about = "Garbage Pile - The verifying OpenPGP key server.")]
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
