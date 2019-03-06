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
extern crate structopt;
extern crate tempfile;

#[cfg(test)]
extern crate fs_extra;
#[cfg(test)]
extern crate regex;

extern crate hagrid_database as database;
mod mail;
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
    /// Use NGINX'es X-Accel-Redirect feature.
    #[structopt(long = "use-x-accel-redirect")]
    x_accel_redirect: bool,
}

fn main() {
    if let Err(e) = real_main() {
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

fn real_main() -> Result<()> {
    use database::{Filesystem, Polymorphic};

    let mut opt = Opt::from_args();
    opt.base = opt.base.canonicalize()?;
    let db = Filesystem::new(&opt.base)?;
    web::serve(&opt, Polymorphic::Filesystem(db))
}
