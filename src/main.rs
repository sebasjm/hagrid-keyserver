#![feature(plugin, decl_macro, custom_derive)]
#![plugin(rocket_codegen)]
#![recursion_limit = "1024"]
#![feature(try_from)]

extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

extern crate time;
extern crate base64;
#[cfg(not(test))] #[macro_use] extern crate rocket;
#[cfg(test)] extern crate rocket;
extern crate openpgp;
extern crate multipart;
#[macro_use] extern crate error_chain;
#[macro_use] extern crate log;
extern crate rand;
extern crate tempfile;
extern crate parking_lot;
#[macro_use] extern crate structopt;

mod web;
mod database;

mod errors {
    error_chain!{
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
            Json(::serde_json::Error);
            Persist(::tempfile::PersistError);
            Base64(::base64::DecodeError);
        }
    }
}
use errors::*;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "garbage", about = "Garbage Pile - The verifying OpenPGP key server.")]
struct Opt {
    /// Debug mode
    #[structopt(short = "v", long = "verbose")]
    debug: bool,
    /// Daemon
    #[structopt(short = "d", long = "daemon")]
    daemon: bool,
    /// Base directory
    #[structopt(parse(from_os_str))]
    base: PathBuf,
    /// Listen
    #[structopt(short = "l", long = "listen", default_value = "0.0.0.0:80")]
    listen: String,
 }

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
}

