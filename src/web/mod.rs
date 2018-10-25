use rocket;
use rocket::{State, Outcome};
use rocket::http::Status;
use rocket::request::{self, Request, FromRequest};
use rocket::response::status::Custom;
use rocket::response::NamedFile;
use rocket::fairing::AdHoc;

use rocket_contrib::Template;
use std::path::{Path, PathBuf};

mod upload;

use database::{Polymorphic, Database};
use types::{Fingerprint, Email};
use errors::Result;
use Opt;

use std::str::FromStr;
use std::result;

mod queries {
    use types::{Fingerprint, Email};

    #[derive(Debug)]
    pub enum Hkp {
        Fingerprint(Fingerprint),
        Email(Email),
    }
}

mod templates {
    #[derive(Serialize)]
    pub struct Verify {
        pub verified: bool,
        pub userid: String,
        pub fpr: String,
    }

    #[derive(Serialize)]
    pub struct Delete {
        pub token: String,
        pub fpr: String,
    }

    #[derive(Serialize)]
    pub struct Confirm {
        pub deleted: bool,
    }
}

struct StaticDir(String);

impl<'a, 'r> FromRequest<'a, 'r> for queries::Hkp {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<queries::Hkp, ()> {
        use rocket::request::FormItems;
        use std::collections::HashMap;

        let query = request.uri().query().unwrap_or("");
        let fields = FormItems::from(query).map(|(k,v)| {
            let key = k.url_decode().unwrap_or_default();
            let value = v.url_decode().unwrap_or_default();
            (key, value)
        }).collect::<HashMap<_,_>>();

        if fields.len() == 2 && fields.get("op").map(|x| x  == "get").unwrap_or(false) {
            let search = fields.get("search").cloned().unwrap_or_default();

            if search.len() == 16 + 2 && search.starts_with("0x") {
                let maybe_fpr = Fingerprint::from_str(&search[2..]);

                match maybe_fpr {
                    Ok(fpr) => Outcome::Success(queries::Hkp::Fingerprint(fpr)),
                    Err(_) => Outcome::Failure((Status::BadRequest, ())),
                }
            } else {
                match Email::from_str(&search) {
                    Ok(email) => Outcome::Success(queries::Hkp::Email(email)),
                    Err(_) => Outcome::Failure((Status::BadRequest, ())),
                }
            }
        } else {
            Outcome::Failure((Status::BadRequest, ()))
        }
    }
}

fn process_key(bytes: &[u8]) -> result::Result<String, Custom<String>> {
    use std::io::Write;
    use openpgp::armor::{Writer, Kind};

    let key = || -> Result<String> {
        let mut buffer = Vec::default();
        {
            let mut writer = Writer::new(&mut buffer, Kind::PublicKey, &[])?;
            writer.write_all(&bytes)?;
        }

        Ok(String::from_utf8(buffer)?)
    }();

    match key {
        Ok(s) => Ok(s),
        Err(_) =>
            Err(Custom(Status::InternalServerError,
                       "Failed to ASCII armor key".to_string())),
    }
}

#[get("/static/by-fpr/<fpr>")]
fn by_fpr(db: rocket::State<Polymorphic>, fpr: String)
    -> result::Result<String, Custom<String>>
{
    let maybe_key = match Fingerprint::from_str(&fpr) {
        Ok(ref fpr) => db.by_fpr(fpr),
        Err(_) => None,
    };

    match maybe_key {
        Some(ref bytes) => process_key(bytes),
        None => Ok("No such key :-(".to_string()),
    }
}

#[get("/static/by-email/<email>")]
fn by_email(db: rocket::State<Polymorphic>, email: String)
    -> result::Result<String, Custom<String>>
{
    let maybe_key = match Email::from_str(&email) {
        Ok(ref email) => db.by_email(email),
        Err(_) => None,
    };

    match maybe_key {
        Some(ref bytes) => process_key(bytes),
        None => Ok("No such key :-(".to_string()),
    }
}

#[get("/verify/<token>")]
fn verify(db: rocket::State<Polymorphic>, token: String)
    -> result::Result<Template, Custom<String>>
{
    match db.verify_token(&token) {
        Ok(Some((userid, fpr))) => {
            let context = templates::Verify{
                verified: true,
                userid: userid.to_string(),
                fpr: fpr.to_string(),
            };

            Ok(Template::render("verify", context))
        }
        Ok(None) | Err(_) => {
            let context = templates::Verify{
                verified: false,
                userid: "".into(),
                fpr: "".into(),
            };

            Ok(Template::render("verify", context))
        }
    }
}

#[get("/delete/<fpr>")]
fn delete(db: rocket::State<Polymorphic>, fpr: String)
    -> result::Result<Template, Custom<String>>
{
    let fpr = match Fingerprint::from_str(&fpr) {
        Ok(fpr) => fpr,
        Err(_) => {
            return Err(Custom(Status::BadRequest,
                              "Invalid fingerprint".to_string()));
        }
    };

    match db.request_deletion(fpr.clone()) {
        Ok(token) => {
            let context = templates::Delete{
                fpr: fpr.to_string(),
                token: token,
            };

            Ok(Template::render("delete", context))
        }
        Err(e) => Err(Custom(Status::InternalServerError,
                             format!("{}", e))),
    }
}

#[get("/confirm/<token>")]
fn confirm(db: rocket::State<Polymorphic>, token: String)
    -> result::Result<Template, Custom<String>>
{
    match db.confirm_deletion(&token) {
        Ok(true) => {
            let context = templates::Confirm{
                deleted: true,
            };

            Ok(Template::render("confirm", context))
        }
        Ok(false) | Err(_) => {
            let context = templates::Confirm{
                deleted: false,
            };

            Ok(Template::render("confirm", context))
        }
    }
}

#[get("/static/<file..>")]
fn files(file: PathBuf, static_dir: State<StaticDir>) -> Option<NamedFile> {
    NamedFile::open(Path::new(&static_dir.0).join(file)).ok()
}

#[get("/pks/lookup")]
fn hkp(db: rocket::State<Polymorphic>, key: Option<queries::Hkp>)
    -> result::Result<String, Custom<String>>
{
    use std::io::Write;
    use openpgp::armor::{Writer, Kind};

    eprintln!("{:?}", key);
    let maybe_key = match key {
        Some(queries::Hkp::Fingerprint(ref fpr)) => db.by_fpr(fpr),
        Some(queries::Hkp::Email(ref email)) => db.by_email(email),
        None => { return Ok("nothing to do".to_string()); }
    };

    match maybe_key {
        Some(bytes) => {
            let key = || -> Result<String> {
                let mut buffer = Vec::default();
                {
                    let mut writer = Writer::new(&mut buffer, Kind::PublicKey, &[])?;
                    writer.write_all(&bytes)?;
                }

                Ok(String::from_utf8(buffer)?)
            }();

            match key {
                Ok(s) => Ok(s),
                Err(_) =>
                    Err(Custom(Status::InternalServerError,
                               "Failed to ASCII armor key".to_string())),
            }
        }
        None => Ok("No such key :-(".to_string()),
    }
}

#[get("/")]
fn root() -> Template {
    use std::collections::HashMap;

    Template::render("index", HashMap::<String, String>::default())
}

pub fn serve(opt: &Opt, db: Polymorphic) -> Result<()> {
    use rocket::config::{Config, Environment};
    use std::str::FromStr;

    let (addr, port) = match opt.listen.find(':') {
        Some(p) => {
            let addr = opt.listen[0..p].to_string();
            let port = if p < opt.listen.len() - 1 {
                u16::from_str(&opt.listen[p+1..]).ok().unwrap_or(8080)
            } else {
                8080
            };

            (addr, port)
        }
        None => (opt.listen.to_string(), 8080)
    };

    let config = Config::build(Environment::Staging)
        .address(addr)
        .port(port)
        .workers(2)
        .root(opt.base.join("static"))
        .extra("template_dir", format!("{}/templates", opt.base.display()))
        .extra("static_dir", format!("{}/public", opt.base.display()))
        .finalize()?;
    let routes = routes![
        upload::multipart_upload,
        by_email,
        by_fpr,
        verify,
        delete,
        confirm,
        root,
        files,
        hkp,
    ];

    rocket::custom(config, opt.verbose)
        .attach(Template::fairing())
        .attach(AdHoc::on_attach(|rocket| {
            let static_dir = rocket.config()
                .get_str("static_dir")
                .unwrap()
                .to_string();

            Ok(rocket.manage(StaticDir(static_dir)))
        }))
        .mount("/", routes)
        .manage(db)
        .launch();
    Ok(())
}

//POST /keys
//GET /keys/<fpr>

