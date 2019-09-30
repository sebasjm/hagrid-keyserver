#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]

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
#[macro_use]
extern crate rocket_contrib;

extern crate sequoia_openpgp;
extern crate handlebars;
extern crate lazy_static;
extern crate lettre;
extern crate lettre_email;
extern crate rocket_prometheus;
extern crate tempfile;
extern crate uuid;
extern crate glob;

extern crate gettext;
extern crate gettext_macros;
extern crate rocket_i18n;
extern crate runtime_fmt;

#[cfg(test)]
extern crate regex;

extern crate ring;

extern crate hagrid_database as database;

use gettext_macros::init_i18n;

init_i18n!("hagrid", en, de);

mod mail;
mod anonymize_utils;
mod tokens;
mod sealed_state;
mod rate_limiter;
mod dump;
mod counters;
mod i18n;
mod template_helpers;
mod gettext_strings;
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
