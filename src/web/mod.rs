use rocket;
use rocket::http::Header;
use rocket::response::NamedFile;
use rocket::config::Config;
use rocket_contrib::templates::Template;

use serde::Serialize;
use handlebars::Handlebars;

use std::path::PathBuf;

pub mod upload;
use mail;
use tokens;

use database::{Database, Polymorphic, Query};
use database::types::{Email, Fingerprint, KeyID};
use Result;

use std::str::FromStr;

mod hkp;
mod manage;

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
    #[response(status = 400, content_type = "html")]
    BadRequest(Template),
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

    // XXX needs fixing for keys_dir!
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

    pub fn bad_request(template: &'static str, e: failure::Error) -> Self {
        let ctx = templates::General {
            error: Some(format!("{}", e)),
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
        };
        MyResponse::BadRequest(Template::render(template, ctx))
    }

    pub fn not_found<M>(tmpl: Option<&'static str>, message: M)
                        -> Self
        where M: Into<Option<String>>,
    {
        MyResponse::NotFound(
            Template::render(
                tmpl.unwrap_or("index"),
                templates::General::new(
                    Some(message.into()
                         .unwrap_or_else(|| "Key not found".to_owned())))))
    }
}

mod templates {
    #[derive(Serialize)]
    pub struct Verify {
        pub verified: bool,
        pub userid: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Search {
        pub query: String,
        pub gpg_options: Option<&'static str>,
        pub fpr: String,
        pub base_uri: String,
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
    pub struct General {
        pub error: Option<String>,
        pub commit: String,
        pub version: String,
    }

    impl General {
        pub fn new(error: Option<String>) -> Self {
            Self {
                error: error,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            }
        }
    }

    impl Default for General {
        fn default() -> Self {
            Self::new(None)
        }
    }
}

pub struct HagridState {
    /// State directory, used internally by hagrid
    state_dir: PathBuf,

    /// Assets directory, mounted to /assets, served by hagrid or nginx
    assets_dir: PathBuf,

    /// The keys directory, where keys are located, served by hagrid or nginx
    keys_dir: PathBuf,

    /// XXX
    base_uri: String,

    /// Controls the use of NGINX'es XAccelRedirect feature.
    x_accel_redirect: bool,
}

fn key_to_response<'a>(state: rocket::State<HagridState>,
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
        base_uri: state.base_uri.clone(),
        fpr: fp.to_string(),
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    MyResponse::ok("found", context)
}

fn key_has_uids(state: &HagridState, db: &Polymorphic, query: &Query)
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
fn vks_v1_by_fingerprint(state: rocket::State<HagridState>,
                         db: rocket::State<Polymorphic>,
                         fpr: String) -> MyResponse {
    let query = match Fingerprint::from_str(&fpr) {
        Ok(fpr) => Query::ByFingerprint(fpr),
        Err(e) => return MyResponse::bad_request("index", e),
    };

    key_to_response(state, db, fpr, query, true)
}

#[get("/vks/v1/by-email/<email>")]
fn vks_v1_by_email(state: rocket::State<HagridState>,
                   db: rocket::State<Polymorphic>,
                   email: String) -> MyResponse {
    let query = match Email::from_str(&email) {
        Ok(email) => Query::ByEmail(email),
        Err(e) => return MyResponse::bad_request("index", e),
    };

    key_to_response(state, db, email, query, true)
}

#[get("/vks/v1/by-keyid/<kid>")]
fn vks_v1_by_keyid(state: rocket::State<HagridState>,
                   db: rocket::State<Polymorphic>,
                   kid: String) -> MyResponse {
    let query = match KeyID::from_str(&kid) {
        Ok(keyid) => Query::ByKeyID(keyid),
        Err(e) => return MyResponse::bad_request("index", e),
    };

    key_to_response(state, db, kid, query, true)
}

#[get("/publish/<token>")]
fn publish_verify(db: rocket::State<Polymorphic>,
                  token: String) -> MyResponse {
    match db.verify_token(&token) {
        Ok(Some((userid, _fpr))) => {
            let context = templates::Verify {
                verified: true,
                userid: userid.to_string(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            MyResponse::ok("publish-result", context)
        }
        Ok(None) => MyResponse::not_found(Some("generic-error"), None),
        Err(e) => MyResponse::ise(e),
    }
}

#[get("/assets/<file..>")]
fn files(file: PathBuf, state: rocket::State<HagridState>) -> Option<NamedFile> {
    NamedFile::open(state.assets_dir.join(file)).ok()
}

#[get("/")]
fn root() -> Template {
    Template::render("index", templates::General::default())
}

#[get("/about")]
fn about() -> Template {
    Template::render("about/about", templates::General::default())
}

#[get("/about/privacy")]
fn privacy() -> Template {
    Template::render("about/privacy", templates::General::default())
}

#[get("/about/api")]
fn apidoc() -> Template {
    Template::render("about/api", templates::General::default())
}

pub fn serve() -> Result<()> {
    Err(rocket_factory(rocket::ignite())?.launch().into())
}

fn rocket_factory(rocket: rocket::Rocket) -> Result<rocket::Rocket> {
    let routes = routes![
        // infra
        root,
        about,
        privacy,
        apidoc,
        files,
        // VKSv1
        vks_v1_by_email,
        vks_v1_by_fingerprint,
        vks_v1_by_keyid,
        upload::vks_v1_publish_post,
        // User interaction.
        upload::publish,
        publish_verify,
        // HKP
        hkp::pks_lookup,
        hkp::pks_add,
        // EManage
        manage::vks_manage,
        manage::vks_manage_key,
        manage::vks_manage_post,
        manage::vks_manage_unpublish,
    ];

    let db_service = configure_db_service(rocket.config())?;
    let hagrid_state = configure_hagrid_state(rocket.config())?;
    let token_service = configure_token_service(rocket.config())?;
    let mail_service = configure_mail_service(rocket.config())?;

    Ok(rocket
       .attach(Template::fairing())
       .manage(hagrid_state)
       .manage(token_service)
       .manage(mail_service)
       .manage(db_service)
       .mount("/", routes)
      )
}

fn configure_db_service(config: &Config) -> Result<Polymorphic> {
    use database::{Filesystem, Polymorphic};

    let keys_dir: PathBuf = config.get_str("keys_dir")?.into();
    let state_dir: PathBuf = config.get_str("state_dir")?.into();
    let tmp_dir: PathBuf = config.get_str("tmp_dir")?.into();

    let fs_db = Filesystem::new(keys_dir, state_dir, tmp_dir)?;
    Ok(Polymorphic::Filesystem(fs_db))
}

fn configure_hagrid_state(config: &Config) -> Result<HagridState> {
    let state_dir: PathBuf = config.get_str("state_dir")?.into();
    let assets_dir: PathBuf = config.get_str("assets_dir")?.into();
    let keys_dir: PathBuf = config.get_str("keys_dir")?.into();

    // State
    let base_uri = config.get_str("base-URI")?.to_string();
    Ok(HagridState {
        state_dir,
        assets_dir,
        keys_dir,
        base_uri: base_uri.clone(),
        x_accel_redirect: config.get_bool("x-accel-redirect")?,
    })
}

fn configure_token_service(config: &Config) -> Result<tokens::Service> {
    use std::convert::TryFrom;

    let secret = config.get_str("token_secret")?.to_string();
    let validity = config.get_int("token_validity")?;
    let validity = u64::try_from(validity)?;
    Ok(tokens::Service::init(&secret, validity))
}

fn configure_mail_service(config: &Config) -> Result<mail::Service> {
    // Mail service
    let template_dir: PathBuf = config.get_str("template_dir")?.into();
    let base_uri = config.get_str("base-URI")?.to_string();
    let from = config.get_str("from")?.to_string();
    let verify_html = template_dir.join("email/publish-html.hbs");
    let verify_txt = template_dir.join("email/publish-txt.hbs");
    let manage_html = template_dir.join("email/manage-html.hbs");
    let manage_txt = template_dir.join("email/manage-txt.hbs");

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("verify-html", verify_html)?;
    handlebars.register_template_file("verify-txt", verify_txt)?;
    handlebars.register_template_file("manage-html", manage_html)?;
    handlebars.register_template_file("manage-txt", manage_txt)?;

    let filemail_into = config.get_str("filemail_into")
        .ok().map(|p| PathBuf::from(p));

    if let Some(path) = filemail_into {
        mail::Service::filemail(from, base_uri, handlebars, path)
    } else {
        mail::Service::sendmail(from, base_uri, handlebars)
    }
}

#[cfg(test)]
pub mod tests {
    use regex;
    use std::fs;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};
    use super::rocket;
    use rocket::local::{Client, LocalResponse};
    use rocket::http::Status;
    use rocket::http::ContentType;
    use lettre::{SendableEmail, SimpleSendableEmail};

    use sequoia_openpgp::TPK;
    use sequoia_openpgp::tpk::TPKBuilder;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::Serialize;

    use database::*;
    use super::*;

    /// Fake base URI to use in tests.
    const BASE_URI: &'static str = "http://local.connection";

    /// Creates a configuration and empty state dir for testing purposes.
    ///
    /// Note that you need to keep the returned TempDir alive for the
    /// duration of your test.  To debug the test, mem::forget it to
    /// prevent cleanup.
    pub fn configuration() -> Result<(TempDir, rocket::Config)> {
        use rocket::config::{Config, Environment};

        let root = tempdir()?;
        let filemail = root.path().join("filemail");
        ::std::fs::create_dir_all(&filemail)?;

        let base_dir: PathBuf = root.path().into();

        let config = Config::build(Environment::Staging)
            .root(root.path().to_path_buf())
            .extra("template_dir",
                   ::std::env::current_dir().unwrap().join("dist/templates")
                   .to_str().unwrap())
            .extra("assets_dir",
                   ::std::env::current_dir().unwrap().join("dist/assets")
                   .to_str().unwrap())
            .extra("keys_dir", base_dir.join("keys").to_str().unwrap())
            .extra("tmp_dir", base_dir.join("tmp").to_str().unwrap())
            .extra("state_dir", base_dir.join("state").to_str().unwrap())
            .extra("base-URI", BASE_URI)
            .extra("from", "from")
            .extra("token_secret", "hagrid")
            .extra("token_validity", 3600)
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
        assert!(response.body_string().unwrap().contains("distribution and discovery"));

        // Check that we see the privacy policy.
        let mut response = client.get("/about/privacy").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Public Key Data"));

        // Check that we see the API docs.
        let mut response = client.get("/about/api").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("/vks/v1/by-keyid"));

        // Check that we see the upload form.
        let mut response = client.get("/publish").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("upload"));

        // Check that we see the deletion form.
        let mut response = client.get("/manage").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("verification link"));

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_single() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        vks_publish_submit(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        // Now check for the verification mail.
        check_mails_and_verify_email(&client, filemail_into.as_path());

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk, 1);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 1);

        // Request deletion of the binding.
        vks_manage(&client, "foo@invalid.example.com");

        // Confirm deletion.
        check_mails_and_confirm_deletion(&client, filemail_into.as_path(), "foo@invalid.example.com");

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

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
        vks_publish_submit(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);

        // Now check for the verification mails.
        check_mails_and_verify_email(&client, &filemail_into);
        check_mails_and_verify_email(&client, &filemail_into);

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk_0, 1);
        check_responses_by_email(&client, "bar@invalid.example.com", &tpk_1, 1);

        // Request deletion of the bindings.
        vks_manage(&client, "foo@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "foo@invalid.example.com");
        vks_manage(&client, "bar@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "bar@invalid.example.com");

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_no_key() {
        let (_tmpdir, client) = client().unwrap();
        let response = vks_publish_submit_response(&client, b"");
        assert_eq!(response.status(), Status::BadRequest);
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
    pub fn check_responses_by_email(client: &Client, addr: &str, tpk: &TPK,
                                    nr_uids: usize) {
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr.replace("@", "%40")),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", addr),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", addr),
            &tpk, nr_uids);
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
    /// page that contains a URI pointing to the TPK.
    pub fn check_hr_response(client: &Client, uri: &str, tpk: &TPK,
                             nr_uids: usize) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        let body = response.body_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));

        // Extract the links.
        let link_re = regex::Regex::new(
            &format!("{}(/vks/[^ \t\n\"<]*)", BASE_URI)).unwrap();
        let mut n = 0;
        for link in link_re.captures_iter(&body) {
            check_mr_response(client, link.get(1).unwrap().as_str(), tpk,
                              nr_uids);
            n += 1;
        }
        assert!(n > 0);
    }

    /// Asserts that we can get the given TPK back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_hr_responses_by_fingerprint(client: &Client, tpk: &TPK,
                                             nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = tpk.fingerprint().to_keyid().to_hex();

        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", fp),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search=0x{}", fp),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search={}", keyid),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/pks/lookup?op=get&search=0x{}", keyid),
            &tpk, nr_uids);
    }

    fn check_mails_and_verify_email(client: &Client, filemail_path: &Path) {
        let pattern = format!("{}(/publish/[^ \t\n]*)", BASE_URI);
        let confirm_uri = pop_mail_capture_pattern(filemail_path, &pattern);

        let response = client.get(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn check_mails_and_confirm_deletion(client: &Client, filemail_path: &Path, address: &str) {
        let pattern = format!("{}/manage/([^ \t\n]*)", BASE_URI);
        let token = pop_mail_capture_pattern(filemail_path, &pattern);
        vks_manage_delete(client, &token, address);
    }

    fn pop_mail_capture_pattern(filemail_path: &Path, pattern: &str) -> String {
        let mail_message = pop_mail(filemail_path).unwrap().unwrap();
        let mail_content = mail_message.message();

        let capture_re = regex::bytes::Regex::new(pattern).unwrap();
        let capture_content = capture_re .captures(&mail_content).unwrap()
            .get(1).unwrap().as_bytes();
        String::from_utf8_lossy(capture_content).to_string()
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

    fn vks_publish_submit<'a>(client: &'a Client, data: &[u8]) {
        let response = vks_publish_submit_response(client, data);
        assert_eq!(response.status(), Status::Ok);
    }

    fn vks_publish_submit_response<'a>(client: &'a Client, data: &[u8]) ->
            LocalResponse<'a> {
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
        client.post("/vks/v1/publish")
            .header(ct)
            .body(&body[..])
            .dispatch()
    }

    fn vks_manage<'a>(client: &'a Client, search_term: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("search_term", search_term)
            .finish();
        let response = client.post("/manage")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn vks_manage_delete(client: &Client, token: &str, address: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("address", address)
            .finish();
        let response = client.post("/manage/unpublish")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}
