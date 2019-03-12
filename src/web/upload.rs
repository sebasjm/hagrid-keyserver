use failure;
use failure::Fallible as Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::FlashMessage;
use rocket::response::Redirect;
use rocket::Data;
use rocket_contrib::templates::Template;
use rocket::response::Flash;

use database::{Database, Polymorphic};
use mail;
use web::State;

use std::io::Read;

const UPLOAD_LIMIT: u64 = 1024 * 1024; // 1 MiB.

mod template {
    #[derive(Serialize)]
    pub struct Upload {
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct VerificationError {
        pub error: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub emails: Vec<String>,
        pub commit: String,
        pub version: String,
    }
}

#[get("/publish")]
pub fn publish(
    flash: Option<FlashMessage>
) -> Template {
    if let Some(flash) = flash {
        match flash.name() {
            "success" => {
                let emails: Vec<String> = serde_json::from_str(flash.msg()).unwrap();
                let context = template::VerificationSent {
                    emails: emails,
                    version: env!("VERGEN_SEMVER").to_string(),
                    commit: env!("VERGEN_SHA_SHORT").to_string(),
                };

                Template::render("publish_ok", context)
            }
            _ => show_error(flash.msg().to_owned())
        }
    } else {
        let context = template::Upload {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
        };

        Template::render("publish", context)
    }
}

fn show_error(error: String) -> Template {
    let context = template::VerificationError {
        error,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Template::render("publish_err", context)
}

#[post("/publish", data = "<data>")]
pub fn publish_post(
    db: rocket::State<Polymorphic>, cont_type: &ContentType, data: Data,
    mail_service: rocket::State<mail::Service>, state: rocket::State<State>,
) -> Flash<Redirect> {
    match handle_upload(db, cont_type, data, Some(mail_service), state) {
        Ok(ok) => ok,
        Err(err) => Flash::error(Redirect::to("/publish?err"), err.to_string()),
    }
}

// signature requires the request to have a `Content-Type`
pub fn handle_upload(
    db: rocket::State<Polymorphic>, cont_type: &ContentType, data: Data,
    mail_service: Option<rocket::State<mail::Service>>, state: rocket::State<State>,
) -> Result<Flash<Redirect>> {
    if cont_type.is_form_data() {
        // multipart/form-data
        let (_, boundary) = cont_type.params().find(|&(k, _)| k == "boundary").ok_or_else(
            || failure::err_msg("`Content-Type: multipart/form-data` boundary \
                                 param not provided"))?;

        process_upload(boundary, data, db.inner(), mail_service, &state.domain)
    } else if cont_type.is_form() {
        use rocket::request::FormItems;
        use std::io::Cursor;

        // application/x-www-form-urlencoded
        let mut buf = Vec::default();

        std::io::copy(&mut data.open().take(UPLOAD_LIMIT), &mut buf).or_else(
            |_| { Err(failure::err_msg(
                "`Content-Type: application/x-www-form-urlencoded` not valid"))
        })?;

        for item in FormItems::from(&*String::from_utf8_lossy(&buf)) {
            let (key, value) = item.key_value();
            let decoded_value = value.url_decode().or_else(|_| {
                Err(failure::err_msg(
                    "`Content-Type: application/x-www-form-urlencoded` \
                     not valid"))
            })?;

            match key.as_str() {
                "keytext" => {
                    return process_key(
                        Cursor::new(decoded_value.as_bytes()),
                        &db,
                        mail_service,
                        &state.domain,
                    );
                }
                _ => { /* skip */ }
            }
        }

        Err(failure::err_msg("Not a PGP public key"))
    } else {
        Err(failure::err_msg("Content-Type not a form"))
    }
}

fn process_upload(
    boundary: &str, data: Data, db: &Polymorphic,
    mail_service: Option<rocket::State<mail::Service>>,
    domain: &str,
) -> Result<Flash<Redirect>> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(entries, db, mail_service, domain)
        }
        Partial(partial, _) => {
            process_multipart(partial.entries, db, mail_service, domain)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(entries: Entries, db: &Polymorphic,
                     mail_service: Option<rocket::State<mail::Service>>,
                     domain: &str) -> Result<Flash<Redirect>> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            process_key(reader, db, mail_service, domain)
        }
        Some(_) | None => {
            Err(failure::err_msg("Not a PGP public key"))
        }
    }
}

fn process_key<R>(
    reader: R, db: &Polymorphic, mail_service: Option<rocket::State<mail::Service>>,
    domain: &str,
) -> Result<Flash<Redirect>>
where
    R: Read,
{
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::tpk::TPKParser;

    // First, parse all TPKs and error out if one fails.
    let mut tpks = Vec::new();
    for tpk in TPKParser::from_reader(reader)? {
        tpks.push(tpk?);
    }

    let mut results: Vec<String> = vec!();
    for tpk in tpks {
        let tokens = db.merge_or_publish(&tpk)?;

        if let Some(ref mail_service) = mail_service {
            for (email, token) in tokens {
                mail_service.send_verification(
                    &tpk,
                    &email,
                    &token,
                    domain,
                )?;
                results.push(email.to_string());
            }
        }
    }

    let json = serde_json::to_string(&results).unwrap();
    Ok(Flash::success(Redirect::to("/publish?ok"), json))
}
