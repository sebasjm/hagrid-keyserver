#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

extern crate failure;
use failure::Fallible as Result;

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate time;
extern crate url;

#[macro_use]
extern crate rocket;
extern crate multipart;
extern crate rocket_contrib;

extern crate sequoia_openpgp;
extern crate handlebars;
extern crate lettre;
extern crate lettre_email;
extern crate tempfile;

#[cfg(test)]
extern crate fs_extra;
#[cfg(test)]
extern crate regex;

extern crate hagrid_database as database;
mod mail;
mod web;

fn main() {
    if let Err(e) = web::serve() {
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        ::std::process::exit(2);
    }
}
