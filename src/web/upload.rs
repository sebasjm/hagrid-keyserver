use failure;
use failure::Fallible as Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::Form;
use rocket::Data;

use database::{Database, KeyDatabase, StatefulTokens, EmailAddressStatus, TpkStatus};
use database::types::{Fingerprint,Email};
use mail;
use tokens::{self, StatelessSerializable};
use web::MyResponse;
use rate_limiter::RateLimiter;

use sequoia_openpgp::TPK;

use std::io::Read;
use std::convert::TryFrom;

const UPLOAD_LIMIT: u64 = 1024 * 1024; // 1 MiB.

mod template {
    #[derive(Serialize)]
    pub struct Verify {
        pub verified: bool,
        pub userid: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Publish {
        pub commit: String,
        pub version: String,
        pub show_help: bool,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub commit: String,
        pub version: String,
        pub key_fpr: String,
        pub key_link: String,
        pub is_revoked: bool,
        pub token: String,
        pub uid_status: Vec<PublishUidStatus>,
    }

    #[derive(Serialize)]
    pub struct UploadOkKey {
        pub key_fpr: String,
        pub key_link: String,
    }

    #[derive(Serialize)]
    pub struct UploadOkMultiple {
        pub commit: String,
        pub version: String,
        pub keys: Vec<UploadOkKey>,
    }

    #[derive(Serialize)]
    pub struct PublishUidStatus {
        pub address: String,
        pub requested: bool,
        pub published: bool,
        pub revoked: bool,
    }

}

mod forms {
    #[derive(FromForm)]
    pub struct VerifyRequest {
        pub token: String,
        pub address: String,
    }
}

impl MyResponse {
    fn publish_ok(
        token_stateless: &tokens::Service,
        verify_state: VerifyTpkState,
        uid_status: Vec<template::PublishUidStatus>
    ) -> Self {
        let key_fpr = verify_state.fpr.to_string();
        let key_link = format!("/pks/lookup?op=get&search={}", &verify_state.fpr);
        let token = token_stateless.create(verify_state);

        let context = template::VerificationSent {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            is_revoked: false,
            key_fpr,
            key_link,
            token: token,
            uid_status,
        };

        MyResponse::ok("publish/publish_ok", context)
    }
}

#[derive(Serialize,Deserialize)]
struct VerifyTpkState {
    fpr: Fingerprint,
    addresses: Vec<Email>,
    requested: Vec<Email>,
}

impl StatelessSerializable for VerifyTpkState {
}

impl VerifyTpkState {
    fn with_requested(self, requested_address: Email) -> Self {
        let VerifyTpkState { fpr, addresses, mut requested } = self;
        requested.push(requested_address);
        VerifyTpkState { fpr, addresses, requested }
    }
}

#[get("/publish?<guide>")]
pub fn publish(guide: bool) -> MyResponse {
    let context = template::Publish {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
        show_help: guide,
    };

    MyResponse::ok("publish/publish", context)
}

#[post("/vks/v1/publish", data = "<data>")]
pub fn vks_v1_publish_post(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    cont_type: &ContentType,
    data: Data,
) -> MyResponse {
    match handle_upload(&db, &tokens_stateless, cont_type, data) {
        Ok(ok) => ok,
        Err(err) => MyResponse::ise(err),
    }
}

// signature requires the request to have a `Content-Type`
pub fn handle_upload(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    cont_type: &ContentType,
    data: Data,
) -> Result<MyResponse> {
    if cont_type.is_form_data() {
        // multipart/form-data
        let (_, boundary) =
            match cont_type.params().find(|&(k, _)| k == "boundary") {
                Some(v) => v,
                None => return Ok(MyResponse::bad_request(
                    "publish/publish",
                    failure::err_msg("`Content-Type: multipart/form-data` \
                                      boundary param not provided"))),
            };

        process_upload(db, tokens_stateless, data, boundary)
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
                        db,
                        tokens_stateless,
                        Cursor::new(decoded_value.as_bytes()),
                    );
                }
                _ => { /* skip */ }
            }
        }

        Ok(MyResponse::bad_request("publish/publish",
                                   failure::err_msg("No keytext found")))
    } else {
        Ok(MyResponse::bad_request("publish/publish",
                                   failure::err_msg("Bad Content-Type")))
    }
}

fn process_upload(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    data: Data,
    boundary: &str,
) -> Result<MyResponse> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(entries, db, tokens_stateless)
        }
        Partial(partial, _) => {
            process_multipart(partial.entries, db, tokens_stateless)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(
    entries: Entries, db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
) -> Result<MyResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            process_key(db, tokens_stateless, reader)
        }
        Some(_) =>
            Ok(MyResponse::bad_request(
                "publish/publish", failure::err_msg("Multiple keytexts found"))),
        None =>
            Ok(MyResponse::bad_request(
                "publish/publish", failure::err_msg("No keytext found"))),
    }
}

fn process_key<R>(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    reader: R,
) -> Result<MyResponse>
where
    R: Read,
{
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::tpk::TPKParser;

    // First, parse all TPKs and error out if one fails.
    let parser = match TPKParser::from_reader(reader) {
        Ok(p) => p,
        Err(e) => return Ok(MyResponse::bad_request("publish/publish", e)),
    };
    let mut tpks = Vec::new();
    for tpk in parser {
        tpks.push(match tpk {
            Ok(t) => t,
            Err(e) => return Ok(MyResponse::bad_request("publish/publish", e)),
        });
    }

    match tpks.len() {
        0 => Ok(MyResponse::bad_request("publish/publish",
                                        failure::err_msg("No key submitted"))),
        1 => process_key_single(db, tokens_stateless, tpks.into_iter().next().unwrap()),
        _ => process_key_multiple(db, tpks),
    }
}

fn process_key_single(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    tpk: TPK,
) -> Result<MyResponse> {
    let fp = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    let tpk_status = db.merge(tpk)?;

    let verify_state = {
        let emails = tpk_status.email_status.iter()
            .map(|(email,_)| email.clone())
            .collect();
        VerifyTpkState {
            fpr: fp.clone(),
            addresses: emails,
            requested: vec!(),
        }
    };

    Ok(show_publish_verify(tokens_stateless, tpk_status, verify_state, None))
}

fn process_key_multiple(
    db: &KeyDatabase,
    tpks: Vec<TPK>,
) -> Result<MyResponse> {
    let merged_keys: Vec<_> = tpks
        .into_iter()
        .flat_map(|tpk| Fingerprint::try_from(tpk.fingerprint())
                .map(|fpr| (fpr, tpk)))
        .flat_map(|(fpr, tpk)| db.merge(tpk).map(|_| fpr))
        .map(|fpr| template::UploadOkKey {
            key_fpr: fpr.to_string(),
            key_link: format!("/pks/lookup?op=get&search={}", fpr),
        })
        .collect();

    let context = template::UploadOkMultiple {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
        keys: merged_keys,
    };

    Ok(MyResponse::ok("publish/publish-ok-multiple", context))
}

#[post("/publish/verify", data="<request>")]
pub fn vks_publish_verify(
    db: rocket::State<KeyDatabase>,
    request: Form<forms::VerifyRequest>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
) -> Result<MyResponse> {
    let verify_state = token_stateless.check::<VerifyTpkState>(&request.token)?;
    let tpk_status = db.get_tpk_status(&verify_state.fpr, &verify_state.addresses)?;

    if tpk_status.is_revoked {
        return Ok(show_publish_verify(
                &token_stateless, tpk_status, verify_state, None))
    }

    let email_requested = request.address.parse::<Email>()
        .ok()
        .filter(|email| verify_state.addresses.contains(email))
        .filter(|email| !verify_state.requested.contains(email))
        .filter(|email| tpk_status.email_status.iter()
            .any(|(uid_email, status)|
                uid_email == email && *status == EmailAddressStatus::NotPublished
            ));

    if let Some(email) = email_requested {
        let rate_limit_ok = rate_limiter.action_perform(format!("verify-{}", &email));
        if rate_limit_ok {
            let token_content = (verify_state.fpr.clone(), email.clone());
            let token_str = serde_json::to_string(&token_content)?;
            let token = token_stateful.new_token("verify", token_str.as_bytes())?;

            mail_service.send_verification(
                verify_state.fpr.to_string(),
                &email,
                &token,
            )?;
        }

        Ok(show_publish_verify(&token_stateless, tpk_status, verify_state, Some(email)))
    } else {
        Ok(show_publish_verify(&token_stateless, tpk_status, verify_state, None))
    }

}

fn show_publish_verify(
    token_stateless: &tokens::Service,
    tpk_status: TpkStatus,
    verify_state: VerifyTpkState,
    email_requested: Option<Email>,
) -> MyResponse {
    if tpk_status.is_revoked {
        return MyResponse::publish_ok(&token_stateless, verify_state, vec!())
    }

    let verify_state = if let Some(email_requested) = email_requested {
        verify_state.with_requested(email_requested)
    } else {
        verify_state
    };
    let uid_status: Vec<_> = tpk_status.email_status.iter()
        .map(|(email, status)|
            template::PublishUidStatus {
                address: email.to_string(),
                requested: verify_state.requested.contains(&email),
                published: *status == EmailAddressStatus::Published,
                revoked: *status == EmailAddressStatus::Revoked,
            })
        .collect();

    MyResponse::publish_ok(&token_stateless, verify_state, uid_status)
}

#[get("/publish/<token>")]
pub fn publish_verify(
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<StatefulTokens>,
    token: String,
) -> MyResponse {
    match publish_verify_or_fail(db, token_service, token) {
        Ok(response) => response,
        Err(e) => MyResponse::ise(e),
    }
}

fn publish_verify_or_fail(
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<StatefulTokens>,
    token: String,
) -> Result<MyResponse> {
    let payload = token_service.pop_token("verify", &token)?;
    let (fingerprint, email) = serde_json::from_str(&payload)?;

    db.set_email_published(&fingerprint, &email)?;

    let context = template::Verify {
        verified: true,
        userid: email.to_string(),
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Ok(MyResponse::ok("publish/publish-result", context))
}
