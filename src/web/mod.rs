use rocket;
use rocket::http::Header;
use rocket::response::status::Custom;
use rocket::response::NamedFile;
use rocket_contrib::templates::Template;
use rocket::request::Form;

use serde::Serialize;
use handlebars::Handlebars;

use std::path::PathBuf;

pub mod upload;
use mail;

use database::{Database, Polymorphic, Query};
use database::types::{Email, Fingerprint, KeyID};
use Result;

use std::result;
use std::str::FromStr;

mod hkp;

use rocket::http::hyper::header::ContentDisposition;

#[derive(Responder)]
pub enum MyResponse {
    #[response(status = 200, content_type = "html")]
    Success(Template),
     #[response(status = 200, content_type = "plain")]
    Plain(String),
     #[response(status = 200, content_type = "application/pgp-keys")]
    Key(String, ContentDisposition),
    #[response(status = 200, content_type = "application/pgp-keys")]
    XAccelRedirect(&'static str, Header<'static>, ContentDisposition),
    #[response(status = 500, content_type = "html")]
    ServerError(Template),
    #[response(status = 404, content_type = "html")]
    NotFound(Template),
}

impl MyResponse {
    pub fn ok<S: Serialize>(tmpl: &'static str, ctx: S) -> Self {
        MyResponse::Success(Template::render(tmpl, ctx))
    }

    pub fn plain(s: String) -> Self {
        MyResponse::Plain(s)
    }

    pub fn key(armored_key: String, fp: &Fingerprint) -> Self {
        use rocket::http::hyper::header::{ContentDisposition, DispositionType,
                                          DispositionParam, Charset};
        MyResponse::Key(
            armored_key,
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![
                    DispositionParam::Filename(
                        Charset::Us_Ascii, None,
                        (fp.to_string() + ".asc").into_bytes()),
                ],
            })
    }

    pub fn x_accel_redirect(path: PathBuf, fp: &Fingerprint) -> Self {
        use rocket::http::hyper::header::{ContentDisposition, DispositionType,
                                          DispositionParam, Charset};
        // The path is relative to our base directory, but we need to
        // get it relative to base/public.
        let mut path = path.into_os_string().into_string().expect("valid UTF8");
        // Drop the first component.
        assert!(path.starts_with("public/"));
        path.drain(..6);

        MyResponse::XAccelRedirect(
            "",
            Header::new("X-Accel-Redirect", path),
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![
                    DispositionParam::Filename(
                        Charset::Us_Ascii, None,
                        (fp.to_string() + ".asc").into_bytes()),
                ],
            })
    }

    pub fn ise(e: failure::Error) -> Self {
        let ctx = templates::FiveHundred{
            error: format!("{}", e),
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
        };
        MyResponse::ServerError(Template::render("500", ctx))
    }

    pub fn not_found<M>(tmpl: Option<&'static str>, message: M)
                        -> Self
        where M: Into<Option<String>>,
    {
        MyResponse::NotFound(
            Template::render(
                tmpl.unwrap_or("index"),
                templates::Index::new(
                    Some(message.into()
                         .unwrap_or_else(|| "Key not found".to_owned())))))
    }
}

mod templates {
    #[derive(Serialize)]
    pub struct Verify {
        pub verified: bool,
        pub userid: String,
        pub fpr: String,
        pub domain: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Delete {
        pub fpr: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Search {
        pub query: String,
        pub gpg_options: Option<&'static str>,
        pub fpr: Option<String>,
        pub domain: Option<String>,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Confirm {
        pub deleted: bool,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct FiveHundred {
        pub error: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Index {
        pub error: Option<String>,
        pub commit: String,
        pub version: String,
    }

    impl Index {
        pub fn new(error: Option<String>) -> Self {
            Self {
                error: error,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            }
        }
    }

    #[derive(Serialize)]
    pub struct General {
        pub commit: String,
        pub version: String,
    }

    impl Default for General {
        fn default() -> Self {
            General {
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            }
        }
    }
}

pub struct State {
    /// The base directory.
    state_dir: PathBuf,

    /// The public directory.
    ///
    /// This is what nginx serves.
    public_dir: PathBuf,

    /// XXX
    domain: String,

    /// Controls the use of NGINX'es XAccelRedirect feature.
    x_accel_redirect: bool,
}

fn key_to_response<'a>(state: rocket::State<State>,
                       db: rocket::State<Polymorphic>,
                       query_string: String,
                       query: Query,
                       machine_readable: bool)
                       -> MyResponse {
    let fp = if let Some(fp) = db.lookup_primary_fingerprint(&query) {
        fp
    } else {
        return MyResponse::not_found(None, None);
    };

    if machine_readable {
        if state.x_accel_redirect {
            if let Some(path) = db.lookup_path(&query) {
                return MyResponse::x_accel_redirect(path, &fp);
            }
        }

        return match db.by_fpr(&fp) {
            Some(armored) => MyResponse::key(armored, &fp.into()),
            None => MyResponse::not_found(None, None),
        }
    }

    let has_uids = match key_has_uids(&state, &db, &query) {
        Ok(x) => x,
        Err(e) => return MyResponse::ise(e),
    };

    let context = templates::Search{
        query: query_string,
        gpg_options: if has_uids {
            None
        } else {
            Some("--keyserver-options import-drop-uids ")
        },
        domain: Some(state.domain.clone()),
        fpr: fp.to_string().into(),
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    MyResponse::ok("found", context)
}

fn key_has_uids(state: &State, db: &Polymorphic, query: &Query)
                -> Result<bool> {
    use sequoia_openpgp::Packet;
    use sequoia_openpgp::parse::{Parse, PacketParser, PacketParserResult};
    let mut ppr = match db.lookup_path(query) {
        Some(path) => PacketParser::from_file(&state.state_dir.join(path))?,
        None => return Err(failure::err_msg("key vanished")),
    };

    while let PacketParserResult::Some(pp) = ppr {
        if let Packet::UserID(_) = pp.packet {
            return Ok(true);
        }
        ppr = pp.recurse()?.1;
    }

    Ok(false)
}

#[get("/vks/v1/by-fingerprint/<fpr>")]
fn by_fingerprint(state: rocket::State<State>,
                  db: rocket::State<Polymorphic>,
                  fpr: String) -> MyResponse {
    let query = match Fingerprint::from_str(&fpr) {
        Ok(fpr) => Query::ByFingerprint(fpr),
        Err(e) => return MyResponse::ise(e),
    };

    key_to_response(state, db, fpr, query, true)
}

#[get("/vks/v1/by-email/<email>")]
fn by_email(state: rocket::State<State>,
            db: rocket::State<Polymorphic>,
            email: String) -> MyResponse {
    let query = match Email::from_str(&email) {
        Ok(email) => Query::ByEmail(email),
        Err(e) => return MyResponse::ise(e),
    };

    key_to_response(state, db, email, query, true)
}

#[get("/vks/v1/by-keyid/<kid>")]
fn by_keyid(state: rocket::State<State>,
            db: rocket::State<Polymorphic>,
            kid: String) -> MyResponse {
    let query = match KeyID::from_str(&kid) {
        Ok(keyid) => Query::ByKeyID(keyid),
        Err(e) => return MyResponse::ise(e),
    };

    key_to_response(state, db, kid, query, true)
}

#[get("/vks/v1/verify/<token>")]
fn verify(state: rocket::State<State>,
          db: rocket::State<Polymorphic>,
          token: String) -> MyResponse {
    match db.verify_token(&token) {
        Ok(Some((userid, fpr))) => {
            let context = templates::Verify {
                verified: true,
                domain: state.domain.clone(),
                userid: userid.to_string(),
                fpr: fpr.to_string(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            MyResponse::ok("verify", context)
        }
        Ok(None) => MyResponse::not_found(Some("generic-error"), None),
        Err(e) => MyResponse::ise(e),
    }
}

#[get("/vks/v1/manage")]
fn manage() -> result::Result<Template, Custom<String>> {
    Ok(Template::render("manage", templates::Index::new(None)))
}

#[derive(FromForm)]
struct ManageRequest {
    search_term: String,
}

#[post("/vks/v1/manage", data="<request>")]
fn manage_post(state: rocket::State<State>,
               db: rocket::State<Polymorphic>,
               mail_service: rocket::State<mail::Service>,
               request: Form<ManageRequest>) -> MyResponse {
    use std::convert::TryInto;

    let query = match request.search_term.parse() {
        Ok(query) => query,
        Err(e) => return MyResponse::ise(e),
    };
    let tpk = match db.lookup(&query) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => return MyResponse::not_found(
            Some("manage"),
            Some(format!("No such key found for {:?}", request.search_term))),
        Err(e) => return MyResponse::ise(e),
    };

    match db.request_deletion(tpk.fingerprint().try_into().unwrap()) {
        Ok((token, uids)) => {
            let context = templates::Delete {
                fpr: tpk.fingerprint().to_string(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            if let Err(e) = mail_service.send_confirmation(
                &uids, &token, &state.domain) {
                return MyResponse::ise(e);
            }

            MyResponse::ok("delete", context)
        }
        Err(e) => MyResponse::ise(e),
    }
}

#[get("/vks/v1/confirm/<token>")]
fn confirm(
    db: rocket::State<Polymorphic>, token: String,
) -> result::Result<Template, Custom<String>> {
    match db.confirm_deletion(&token) {
        Ok(true) => {
            let context = templates::Confirm {
                deleted: true,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("confirm", context))
        }
        Ok(false) | Err(_) => {
            let context = templates::Confirm {
                deleted: false,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("confirm", context))
        }
    }
}

#[get("/assets/<file..>")]
fn files(file: PathBuf, state: rocket::State<State>) -> Option<NamedFile> {
    NamedFile::open(state.public_dir.join("assets").join(file)).ok()
}

#[get("/")]
fn root() -> Template {
    Template::render("index", templates::Index::new(None))
}

#[get("/about")]
fn about() -> Template {
    Template::render("about", templates::General::default())
}

#[get("/apidoc")]
fn apidoc() -> Template {
    Template::render("apidoc", templates::General::default())
}

pub fn serve() -> Result<()> {
    Err(rocket_factory(rocket::ignite())?.launch().into())
}

fn rocket_factory(rocket: rocket::Rocket) -> Result<rocket::Rocket> {
    let routes = routes![
        // infra
        root,
        manage,
        manage_post,
        files,
        // nginx-supported lookup
        by_email,
        by_fingerprint,
        by_keyid,
        upload::vks_publish,
        upload::vks_publish_submit,
        // verification & deletion
        verify,
        confirm,
        // HKP
        hkp::pks_lookup,
        hkp::pks_add,
        // about
        about,
        apidoc,
    ];

    use database::{Filesystem, Polymorphic};
    let db = Polymorphic::Filesystem(
        Filesystem::new(&PathBuf::from(rocket.config().get_str("state_dir")?))?
    );

    // State
    let state_dir: PathBuf = rocket.config().get_str("state_dir")?.into();
    let public_dir = state_dir.join("public");
    let state = State {
        state_dir: state_dir,
        public_dir: public_dir,
        domain: rocket.config().get_str("domain")?.to_string(),
        x_accel_redirect: rocket.config().get_bool("x-accel-redirect")?,
    };

    // Mail service
    let template_dir: PathBuf = rocket.config().get_str("template_dir")?.into();
    let from = rocket.config().get_str("from")?.to_string();
    let confirm_html = template_dir.join("confirm-email-html.hbs");
    let confirm_txt = template_dir.join("confirm-email-txt.hbs");
    let verify_html = template_dir.join("verify-email-html.hbs");
    let verify_txt = template_dir.join("verify-email-txt.hbs");

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("confirm-html", confirm_html)?;
    handlebars.register_template_file("confirm-txt", confirm_txt)?;
    handlebars.register_template_file("verify-html", verify_html)?;
    handlebars.register_template_file("verify-txt", verify_txt)?;

    let filemail_into = rocket.config().get_str("filemail_into")
        .ok().map(|p| PathBuf::from(p));
    let mail_service = if let Some(path) = filemail_into {
        mail::Service::filemail(from, handlebars, path)
    } else {
        mail::Service::sendmail(from, handlebars)
    };

    Ok(rocket
       .attach(Template::fairing())
       .manage(state)
       .manage(mail_service)
       .mount("/", routes)
       .manage(db))
}

#[cfg(test)]
pub mod tests {
    use fs_extra;
    use regex;
    use std::fs;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};
    use super::rocket;
    use rocket::local::Client;
    use rocket::http::Status;
    use rocket::http::ContentType;
    use lettre::{SendableEmail, SimpleSendableEmail};

    use sequoia_openpgp::TPK;
    use sequoia_openpgp::tpk::TPKBuilder;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::Serialize;

    use database::*;
    use super::*;

    /// Creates a configuration and empty state dir for testing purposes.
    ///
    /// Note that you need to keep the returned TempDir alive for the
    /// duration of your test.  To debug the test, mem::forget it to
    /// prevent cleanup.
    pub fn configuration() -> Result<(TempDir, rocket::Config)> {
        use rocket::config::{Config, Environment};

        let root = tempdir()?;
        fs_extra::copy_items(&vec!["dist/templates"], &root,
                             &fs_extra::dir::CopyOptions::new())?;
        let filemail = root.path().join("filemail");
        ::std::fs::create_dir_all(&filemail)?;

        let config = Config::build(Environment::Staging)
            .root(root.path().to_path_buf())
            .extra(
                "template_dir",
                root.path().join("templates").to_str()
                    .ok_or(failure::err_msg("Template path invalid"))?,
            )
            .extra(
                "state_dir",
                root.path().to_str()
                    .ok_or(failure::err_msg("Static path invalid"))?,
            )
            .extra("domain", "domain")
            .extra("from", "from")
            .extra("filemail_into", filemail.into_os_string().into_string()
                   .expect("path is valid UTF8"))
            .extra("x-accel-redirect", false)
            .finalize()?;
        Ok((root, config))
    }

    pub fn client() -> Result<(TempDir, Client)> {
        let (tmpdir, config) = configuration()?;
        let rocket = rocket_factory(rocket::custom(config))?;
        Ok((tmpdir, Client::new(rocket)?))
    }

    pub fn assert_consistency(rocket: &rocket::Rocket) {
        let db = rocket.state::<Polymorphic>().unwrap();
        if let Polymorphic::Filesystem(fs) = db {
            fs.check_consistency().unwrap();
        } else {
            unreachable!();
        }
    }

    #[test]
    fn basics() {
        let (_tmpdir, config) = configuration().unwrap();
        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let mut response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Hagrid"));

        // Check that we see the privacy policy.
        let mut response = client.get("/about").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Public Key Data"));

        // Check that we see the API docs.
        let mut response = client.get("/apidoc").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("/vks/v1/by-keyid"));

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let response = vks_publish_submit(&client, &tpk_serialized);
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"),
                   Some("/vks/v1/publish?ok"));

        // Prior to email confirmation, we should not be able to look
        // it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk);

        // Now check for the confirmation mail.
        check_mails_and_confirm(&client, filemail_into.as_path());

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_two() {
        let (tmpdir, config) = configuration().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Generate two keys and upload them.
        let tpk_0 = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap().0;
        let tpk_1 = TPKBuilder::autocrypt(
            None, Some("bar@invalid.example.com".into()))
            .generate().unwrap().0;

        let mut tpk_serialized = Vec::new();
        tpk_0.serialize(&mut tpk_serialized).unwrap();
        tpk_1.serialize(&mut tpk_serialized).unwrap();
        let response = vks_publish_submit(&client, &tpk_serialized);
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"),
                   Some("/vks/v1/publish?ok"));

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_0);
        check_hr_responses_by_fingerprint(&client, &tpk_1);

        // Now check for the confirmation mails.
        check_mails_and_confirm(&client, filemail_into.as_path());
        check_mails_and_confirm(&client, filemail_into.as_path());

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk_0);
        check_responses_by_email(&client, "bar@invalid.example.com", &tpk_1);

        assert_consistency(client.rocket());
    }

    /// Asserts that the given URI 404s.
    pub fn check_null_response(client: &Client, uri: &str) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    /// Asserts that lookups by the given email 404.
    pub fn check_null_responses_by_email(client: &Client, addr: &str) {
        check_null_response(
            &client, &format!("/vks/v1/by-email/{}", addr));
        check_null_response(
            &client, &format!("/pks/lookup?op=get&search={}", addr));
        check_null_response(
            &client, &format!("/pks/lookup?op=get&options=mr&search={}",
                              addr));
    }

    /// Asserts that lookups by the given email are successful.
    pub fn check_responses_by_email(client: &Client, addr: &str, tpk: &TPK) {
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr),
            &tpk, 1);
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr.replace("@", "%40")),
            &tpk, 1);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", addr),
            &tpk, 1);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", addr),
            &tpk);
    }

    /// Asserts that the given URI returns a TPK matching the given
    /// one, with the given number of userids.
    pub fn check_mr_response(client: &Client, uri: &str, tpk: &TPK,
                             nr_uids: usize) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(),
                   Some(ContentType::new("application", "pgp-keys")));
        let body = response.body_string().unwrap();
        assert!(body.contains("END PGP PUBLIC KEY BLOCK"));
        let tpk_ = TPK::from_bytes(body.as_bytes()).unwrap();
        assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
        assert_eq!(tpk.subkeys().map(|skb| skb.subkey().fingerprint())
                   .collect::<Vec<_>>(),
                   tpk_.subkeys().map(|skb| skb.subkey().fingerprint())
                   .collect::<Vec<_>>());
        assert_eq!(tpk_.userids().count(), nr_uids);
    }

    /// Asserts that we can get the given TPK back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_mr_responses_by_fingerprint(client: &Client, tpk: &TPK,
                                             nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = tpk.fingerprint().to_keyid().to_hex();

        check_mr_response(
            &client, &format!("/vks/v1/by-keyid/{}", keyid), &tpk, nr_uids);
        check_mr_response(
            &client, &format!("/vks/v1/by-fingerprint/{}", fp), &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", fp),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", fp),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", keyid),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", keyid),
            &tpk, nr_uids);
    }

    /// Asserts that the given URI returns human readable response
    /// page.
    pub fn check_hr_response(client: &Client, uri: &str, tpk: &TPK) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        let body = response.body_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));
    }

    /// Asserts that we can get the given TPK back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_hr_responses_by_fingerprint(client: &Client, tpk: &TPK) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = tpk.fingerprint().to_keyid().to_hex();

        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", fp),
            &tpk);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search=0x{}", fp),
            &tpk);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", keyid),
            &tpk);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search=0x{}", keyid),
            &tpk);
    }

    fn check_mails_and_confirm(client: &Client, filemail_path: &Path) {
        let confirm_re =
            regex::bytes::Regex::new("https://domain(/vks/v1/verify[^ \t\n]*)")
            .unwrap();
        let confirm_mail = pop_mail(filemail_path).unwrap().unwrap();
        let confirm_bytes = confirm_mail.message();
        // eprintln!("{}", String::from_utf8_lossy(&confirm_bytes));
        let confirm_link =
            confirm_re.captures(&confirm_bytes).unwrap()
            .get(1).unwrap().as_bytes();
        let confirm_uri = String::from_utf8_lossy(confirm_link).to_string();
        let response = client.get(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    /// Returns and removes the first mail it finds from the given
    /// directory.
    pub fn pop_mail(dir: &Path) -> Result<Option<SimpleSendableEmail>> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let fh = fs::File::open(entry.path())?;
                fs::remove_file(entry.path())?;
                let mail: SimpleSendableEmail =
                    ::serde_json::from_reader(fh)?;
                return Ok(Some(mail));
            }
        }
        Ok(None)
    }

    fn vks_publish_submit<'a>(client: &'a Client, data: &[u8])
                              -> rocket::local::LocalResponse<'a> {
        let ct = ContentType::with_params(
            "multipart", "form-data",
            ("boundary", "---------------------------14733842173518794281682249499"));

        let header =
            b"-----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"csrf\"\r\n\
              \r\n\
              \r\n\
              -----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"keytext\"; filename=\".k\"\r\n\
              Content-Type: application/octet-stream\r\n\
              \r\n";
        let footer = b"\r\n-----------------------------14733842173518794281682249499--";

        let mut body = Vec::new();
        body.extend_from_slice(header);
        body.extend_from_slice(data);
        body.extend_from_slice(footer);
        client.post("/vks/v1/publish/submit")
            .header(ct)
            .body(&body[..])
            .dispatch()
    }
}
