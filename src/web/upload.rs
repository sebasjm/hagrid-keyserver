use failure;
use failure::Fallible as Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::Data;

use database::{Database, KeyDatabase, StatefulTokens};
use database::types::Fingerprint;
use mail;
use web::MyResponse;

use std::io::Read;
use std::convert::TryFrom;

const UPLOAD_LIMIT: u64 = 1024 * 1024; // 1 MiB.

mod template {
    #[derive(Serialize)]
    pub struct Publish {
        pub commit: String,
        pub version: String,
        pub show_help: bool,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub emails: Vec<String>,
        pub commit: String,
        pub version: String,
    }
}

#[get("/publish?<guide>")]
pub fn publish(guide: bool) -> MyResponse {
    let context = template::Publish {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
        show_help: guide,
    };

    MyResponse::ok("publish", context)
}

#[post("/vks/v1/publish", data = "<data>")]
pub fn vks_v1_publish_post(
    db: rocket::State<KeyDatabase>,
    mail_service: rocket::State<mail::Service>,
    token_service: rocket::State<StatefulTokens>,
    cont_type: &ContentType,
    data: Data,
) -> MyResponse {
    match handle_upload(db, cont_type, data, Some((mail_service, token_service))) {
        Ok(ok) => ok,
        Err(err) => MyResponse::ise(err),
    }
}
pub fn handle_upload_without_verify(
    db: rocket::State<KeyDatabase>,
    cont_type: &ContentType,
    data: Data,
) -> Result<MyResponse> {
    handle_upload(db, cont_type, data, None)
}

// signature requires the request to have a `Content-Type`
pub fn handle_upload(
    db: rocket::State<KeyDatabase>, cont_type: &ContentType, data: Data,
    services: Option<(rocket::State<mail::Service>, rocket::State<StatefulTokens>)>,
) -> Result<MyResponse> {
    if cont_type.is_form_data() {
        // multipart/form-data
        let (_, boundary) =
            match cont_type.params().find(|&(k, _)| k == "boundary") {
                Some(v) => v,
                None => return Ok(MyResponse::bad_request(
                    "publish",
                    failure::err_msg("`Content-Type: multipart/form-data` \
                                      boundary param not provided"))),
            };

        process_upload(boundary, data, db.inner(), services)
    } else if cont_type.is_form() {
        use rocket::request::FormItems;
        use std::io::Cursor;

        // application/x-www-form-urlencoded
        let mut buf = Vec::default();

        std::io::copy(&mut data.open().take(UPLOAD_LIMIT), &mut buf)?;

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
                        services,
                    );
                }
                _ => { /* skip */ }
            }
        }

        Ok(MyResponse::bad_request("publish",
                                   failure::err_msg("No keytext found")))
    } else {
        Ok(MyResponse::bad_request("publish",
                                   failure::err_msg("Bad Content-Type")))
    }
}

fn process_upload(
    boundary: &str, data: Data, db: &KeyDatabase,
    services: Option<(rocket::State<mail::Service>, rocket::State<StatefulTokens>)>,
) -> Result<MyResponse> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(entries, db, services)
        }
        Partial(partial, _) => {
            process_multipart(partial.entries, db, services)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(
    entries: Entries, db: &KeyDatabase,
    services: Option<(rocket::State<mail::Service>, rocket::State<StatefulTokens>)>,
) -> Result<MyResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            process_key(reader, db, services)
        }
        Some(_) =>
            Ok(MyResponse::bad_request(
                "publish", failure::err_msg("Multiple keytexts found"))),
        None =>
            Ok(MyResponse::bad_request(
                "publish", failure::err_msg("No keytext found"))),
    }
}

fn process_key<R>(
    reader: R,
    db: &KeyDatabase,
    services: Option<(rocket::State<mail::Service>, rocket::State<StatefulTokens>)>,
) -> Result<MyResponse>
where
    R: Read,
{
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::tpk::TPKParser;

    // First, parse all TPKs and error out if one fails.
    let parser = match TPKParser::from_reader(reader) {
        Ok(p) => p,
        Err(e) => return Ok(MyResponse::bad_request("publish", e)),
    };
    let mut tpks = Vec::new();
    for tpk in parser {
        tpks.push(match tpk {
            Ok(t) => t,
            Err(e) => return Ok(MyResponse::bad_request("publish", e)),
        });
    }

    if tpks.is_empty() {
        return Ok(MyResponse::bad_request(
            "publish",
            failure::err_msg("No key submitted")));
    }

    let mut results: Vec<String> = vec!();
    for tpk in tpks {
        let tpk_name = tpk.fingerprint().to_string();
        let tpk_fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
        let unpublished_emails = db.merge(tpk)?;

        if let Some((ref mail_service, ref token_service)) = services {
            for email in unpublished_emails {
                let token_content = serde_json::to_string(&(tpk_fpr.clone(), email.clone()))?;
                let token = token_service.new_token("verify", token_content.as_bytes())?;
                mail_service.send_verification(
                    tpk_name.clone(),
                    &email,
                    &token,
                )?;
                results.push(email.to_string());
            }
        }
    }

    let context = template::VerificationSent {
        emails: results,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Ok(MyResponse::ok("publish_ok", context))
}
