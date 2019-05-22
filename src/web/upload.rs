use failure;
use failure::Fallible as Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::Form;
use rocket::Data;

use rocket_contrib::json::Json;

use database::{Database, KeyDatabase, StatefulTokens, EmailAddressStatus, TpkStatus};
use database::types::{Fingerprint,Email};
use mail;
use tokens::{self, StatelessSerializable};
use web::MyResponse;
use rate_limiter::RateLimiter;

use sequoia_openpgp::TPK;

use std::io::Read;
use std::convert::TryFrom;
use std::collections::HashMap;

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
    pub struct Upload {
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
        pub uid_status: Vec<UploadUidStatus>,
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
    pub struct UploadUidStatus {
        pub address: String,
        pub requested: bool,
        pub published: bool,
        pub revoked: bool,
    }

}

mod forms {
    #[derive(FromForm,Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub address: String,
    }

    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }
}

#[derive(Debug,Serialize,Deserialize,PartialEq,Eq)]
pub enum EmailStatus {
    #[serde(rename = "unpublished")]
    Unpublished,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "published")]
    Published,
    #[serde(rename = "revoked")]
    Revoked,
}

pub mod json {
    use std::collections::HashMap;
    use super::EmailStatus;

    #[derive(Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub addresses: Vec<String>,
    }

    #[derive(Serialize,Deserialize)]
    pub struct UploadResult {
        pub token: String,
        pub key_fpr: String,
        pub status: HashMap<String,EmailStatus>,
    }
}

pub enum OutputType {
    HumanReadable,
    Json,
}

impl MyResponse {
    fn upload_ok(
        token: String,
        verify_state: VerifyTpkState,
        uid_status: HashMap<String,EmailStatus>,
        output_type: OutputType,
    ) -> Self {
        let key_fpr = verify_state.fpr.to_string();
        let key_link = format!("/pks/lookup?op=get&search={}", &verify_state.fpr);

        match output_type {
            OutputType::HumanReadable =>
                Self::upload_ok_hr(token, key_fpr, key_link, uid_status),
            OutputType::Json =>
                Self::upload_ok_json(token, key_fpr, uid_status),
        }
    }

    fn upload_ok_json(
        token: String,
        key_fpr: String,
        uid_status: HashMap<String,EmailStatus>,
    ) -> MyResponse {
        let result = json::UploadResult { token, key_fpr, status: uid_status };
        MyResponse::Json(serde_json::to_string(&result).unwrap())
    }

    fn upload_ok_hr(
        token: String,
        key_fpr: String,
        key_link: String,
        uid_status: HashMap<String,EmailStatus>,
    ) -> MyResponse {
        let mut uid_status: Vec<_> = uid_status
            .into_iter()
            .map(|(email,status)|
                template::UploadUidStatus {
                    address: email.to_string(),
                    requested: status == EmailStatus::Pending,
                    published: status == EmailStatus::Published,
                    revoked: status == EmailStatus::Revoked,
                })
            .collect();
        uid_status.sort_by(|fst,snd| {
            fst.revoked.cmp(&snd.revoked).then(fst.address.cmp(&snd.address))
        });

        let context = template::VerificationSent {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            is_revoked: false, key_fpr, key_link, token, uid_status,
        };
        MyResponse::ok("upload/upload-ok", context)
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

#[get("/upload?<guide>")]
pub fn upload(guide: bool) -> MyResponse {
    let context = template::Upload {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
        show_help: guide,
    };

    MyResponse::ok("upload/upload", context)
}

#[post("/vks/v1/upload", format = "json", data = "<data>")]
pub fn vks_v1_upload_post_json(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    data: Json<forms::UploadRequest>,
) -> Result<MyResponse> {
    use std::io::Cursor;
    let data_reader = Cursor::new(data.keytext.as_bytes());
    process_key(&db, &tokens_stateless, &rate_limiter, data_reader, OutputType::Json)
}

#[post("/vks/v1/upload", format = "multipart/form-data", data = "<data>")]
pub fn vks_v1_upload_post_form_data(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    cont_type: &ContentType,
    data: Data,
) -> Result<MyResponse> {
    // multipart/form-data
    let (_, boundary) =
        match cont_type.params().find(|&(k, _)| k == "boundary") {
            Some(v) => v,
            None => return Ok(MyResponse::bad_request(
                "upload/upload",
                failure::err_msg("`Content-Type: multipart/form-data` \
                                    boundary param not provided"))),
        };

    process_upload(&db, &tokens_stateless, &rate_limiter, data, boundary, OutputType::HumanReadable)
}

#[post("/vks/v1/upload", format = "application/x-www-form-urlencoded", data = "<data>")]
pub fn vks_v1_upload_post_form(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    data: Data,
) -> Result<MyResponse> {
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
                    &db,
                    &tokens_stateless,
                    &rate_limiter,
                    Cursor::new(decoded_value.as_bytes()),
                    OutputType::HumanReadable,
                );
            }
            _ => { /* skip */ }
        }
    }

    Ok(MyResponse::bad_request("upload/upload",
                                failure::err_msg("No keytext found")))
}

fn process_upload(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    data: Data,
    boundary: &str,
    output_type: OutputType,
) -> Result<MyResponse> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(db, tokens_stateless, rate_limiter, entries, output_type)
        }
        Partial(partial, _) => {
            process_multipart(db, tokens_stateless, rate_limiter, partial.entries, output_type)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    entries: Entries,
    output_type: OutputType,
) -> Result<MyResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            process_key(db, tokens_stateless, rate_limiter, reader, output_type)
        }
        Some(_) =>
            Ok(MyResponse::bad_request(
                "upload/upload", failure::err_msg("Multiple keytexts found"))),
        None =>
            Ok(MyResponse::bad_request(
                "upload/upload", failure::err_msg("No keytext found"))),
    }
}

fn process_key(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    reader: impl Read,
    output_type: OutputType,
) -> Result<MyResponse> {
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::tpk::TPKParser;

    // First, parse all TPKs and error out if one fails.
    let parser = match TPKParser::from_reader(reader) {
        Ok(p) => p,
        Err(e) => return Ok(MyResponse::bad_request("upload/upload", e)),
    };
    let mut tpks = Vec::new();
    for tpk in parser {
        tpks.push(match tpk {
            Ok(t) => {
                if t.is_tsk() {
                    return Ok(MyResponse::bad_request("upload/upload",
                        failure::err_msg("Whoops, please don't upload secret keys!")));
                }
                t
            },
            Err(e) => return Ok(MyResponse::bad_request("upload/upload", e)),
        });
    }

    match tpks.len() {
        0 => Ok(MyResponse::bad_request("upload/upload",
                                        failure::err_msg("No key submitted"))),
        1 => process_key_single(db, tokens_stateless, rate_limiter, tpks.into_iter().next().unwrap(), output_type),
        _ => process_key_multiple(db, tpks),
    }
}

fn process_key_single(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    tpk: TPK,
    output_type: OutputType,
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

    let token = tokens_stateless.create(&verify_state);

    Ok(show_upload_verify(rate_limiter, token, tpk_status, verify_state, output_type))
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

    Ok(MyResponse::ok("upload/upload-ok-multiple", context))
}

#[post("/vks/v1/request-verify", format = "json", data="<request>")]
pub fn vks_upload_verify_json(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    request: Json<json::VerifyRequest>,
) -> Result<MyResponse> {
    let json::VerifyRequest { token, addresses } = request.into_inner();
    vks_upload_verify(db, token_stateful, token_stateless, mail_service,
                       rate_limiter, token, addresses, OutputType::Json)
}

#[post("/vks/v1/request-verify", format = "application/x-www-form-urlencoded", data="<request>")]
pub fn vks_upload_verify_form(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    request: Form<forms::VerifyRequest>,
) -> Result<MyResponse> {
    let forms::VerifyRequest { token, address } = request.into_inner();
    vks_upload_verify(db, token_stateful, token_stateless, mail_service,
                       rate_limiter, token, vec!(address),
                       OutputType::HumanReadable)
}

#[post("/vks/v1/request-verify", format = "multipart/form-data", data="<request>")]
pub fn vks_upload_verify_form_data(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    request: Form<forms::VerifyRequest>,
) -> Result<MyResponse> {
    let forms::VerifyRequest { token, address } = request.into_inner();
    vks_upload_verify(db, token_stateful, token_stateless, mail_service,
                       rate_limiter, token, vec!(address),
                       OutputType::HumanReadable)
}

fn vks_upload_verify(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    token: String,
    addresses: Vec<String>,
    output_type: OutputType,
) -> Result<MyResponse> {
    let verify_state = token_stateless.check::<VerifyTpkState>(&token)?;
    let tpk_status = db.get_tpk_status(&verify_state.fpr, &verify_state.addresses)?;

    if tpk_status.is_revoked {
        return Ok(show_upload_verify(
                &rate_limiter, token, tpk_status, verify_state, output_type))
    }

    let emails_requested: Vec<_> = addresses.into_iter()
        .map(|address| address.parse::<Email>())
        .flatten()
        .filter(|email| verify_state.addresses.contains(email))
        .filter(|email| tpk_status.email_status.iter()
            .any(|(uid_email, status)|
                uid_email == email && *status == EmailAddressStatus::NotPublished
            ))
        .collect();

    for email in emails_requested {
        let rate_limit_ok = rate_limiter.action_perform(format!("verify-{}", &email));
        if rate_limit_ok {
            let token_content = (verify_state.fpr.clone(), email.clone());
            let token_str = serde_json::to_string(&token_content)?;
            let token_verify = token_stateful.new_token("verify", token_str.as_bytes())?;

            mail_service.send_verification(
                verify_state.fpr.to_string(),
                &email,
                &token_verify,
            )?;
        }
    }

    Ok(show_upload_verify(&rate_limiter, token, tpk_status, verify_state, output_type))
}

fn show_upload_verify(
    rate_limiter: &RateLimiter,
    token: String,
    tpk_status: TpkStatus,
    verify_state: VerifyTpkState,
    output_type: OutputType,
) -> MyResponse {
    if tpk_status.is_revoked {
        return MyResponse::upload_ok(token, verify_state, HashMap::new(), output_type)
    }

    let uid_status: HashMap<_,_> = tpk_status.email_status.iter()
        .map(|(email,status)|
                (email.to_string(),
                if !rate_limiter.action_check(format!("verify-{}", &email)) {
                    EmailStatus::Pending
                } else {
                    match status {
                        EmailAddressStatus::NotPublished => EmailStatus::Unpublished,
                        EmailAddressStatus::Published => EmailStatus::Published,
                        EmailAddressStatus::Revoked => EmailStatus::Revoked,
                    }
                }))
        .collect();

    MyResponse::upload_ok(token, verify_state, uid_status, output_type)
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

    Ok(MyResponse::ok("upload/publish-result", context))
}
