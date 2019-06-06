use failure;
use failure::Fallible as Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::Form;
use rocket::Data;

use database::{KeyDatabase, StatefulTokens};
use mail;
use tokens;
use web::{HagridState,MyResponse};
use rate_limiter::RateLimiter;

use std::io::Read;
use std::collections::HashMap;

use web::vks;
use web::vks::response::*;

const UPLOAD_LIMIT: u64 = 1024 * 1024; // 1 MiB.

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
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub commit: String,
        pub version: String,
        pub key_fpr: String,
        pub key_link: String,
        pub is_revoked: bool,
        pub token: String,
        pub email_published: Vec<String>,
        pub email_unpublished: Vec<UploadUidStatus>,
        pub count_revoked_one: bool,
        pub count_revoked: usize,
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
    }

}

impl MyResponse {
    fn upload_response_quick(response: UploadResponse, base_uri: &str) -> Self {
        match response {
            UploadResponse::Ok { token, key_fpr: _, is_revoked: _, status: _ } => {
                let uri = uri!(quick_upload_proceed: token);
                let text = format!(
                    "Key successfully uploaded. Proceed here:\n{}{}\n",
                    base_uri,
                    uri
                );
                MyResponse::plain(text)
            },
            UploadResponse::OkMulti { key_fprs } =>
                MyResponse::plain(format!("Uploaded {} keys.\n", key_fprs.len())),
            UploadResponse::Error(error) => MyResponse::bad_request(
                "500-plain", failure::err_msg(error)),
        }
    }

    fn upload_response(response: UploadResponse) -> Self {
        match response {
            UploadResponse::Ok { token, key_fpr, is_revoked, status } =>
                Self::upload_ok(token, key_fpr, is_revoked, status),
            UploadResponse::OkMulti { key_fprs } =>
                Self::upload_ok_multi(key_fprs),
            UploadResponse::Error(error) => MyResponse::bad_request(
                "upload/upload", failure::err_msg(error)),
        }
    }

    fn upload_ok(
        token: String,
        key_fpr: String,
        is_revoked: bool,
        uid_status: HashMap<String,EmailStatus>,
    ) -> Self {
        let key_link = format!("/pks/lookup?op=get&search={}", &key_fpr);

        let count_revoked = uid_status.iter()
            .filter(|(_,status)| **status == EmailStatus::Revoked)
            .count();

        let mut email_published: Vec<_> = uid_status.iter()
            .filter(|(_,status)| **status == EmailStatus::Published)
            .map(|(email,_)| email.to_string())
            .collect();
        email_published.sort_unstable();

        let mut email_unpublished: Vec<_> = uid_status.into_iter()
            .filter(|(_,status)| *status == EmailStatus::Unpublished ||
                    *status == EmailStatus::Pending)
             .map(|(email,status)|
                 template::UploadUidStatus {
                     address: email.to_string(),
                     requested: status == EmailStatus::Pending,
                 })
            .collect();
        email_unpublished
            .sort_unstable_by(|fst,snd| fst.address.cmp(&snd.address));

        let context = template::VerificationSent {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            is_revoked,
            key_fpr,
            key_link,
            token,
            email_published,
            email_unpublished,
            count_revoked_one: count_revoked == 1,
            count_revoked,
        };
        MyResponse::ok("upload/upload-ok", context)
    }

    fn upload_ok_multi(key_fprs: Vec<String>) -> Self {
        let keys = key_fprs.into_iter()
            .map(|fpr| template::UploadOkKey {
                key_fpr: fpr.to_owned(),
                key_link: format!("/pks/lookup?op=get&search={}", &fpr),
            })
            .collect();

        let context = template::UploadOkMultiple {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            keys,
        };

        MyResponse::ok("upload/upload-ok-multiple", context)
    }
}

#[get("/upload")]
pub fn upload() -> MyResponse {
    let context = template::Upload {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    MyResponse::ok("upload/upload", context)
}

#[post("/upload/submit", format = "multipart/form-data", data = "<data>")]
pub fn upload_post_form_data(
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

    process_upload(&db, &tokens_stateless, &rate_limiter, data, boundary)
}

#[put("/", data = "<data>")]
pub fn quick_upload(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    state: rocket::State<HagridState>,
    data: Data,
) -> MyResponse {
    use std::io::Cursor;

    let mut buf = Vec::default();
    if let Err(error) = std::io::copy(&mut data.open().take(UPLOAD_LIMIT), &mut buf) {
        return MyResponse::bad_request("400-plain", failure::err_msg(error));
    }

    MyResponse::upload_response_quick(vks::process_key(
                        &db,
                        &tokens_stateless,
                        &rate_limiter,
                        Cursor::new(buf)), &state.base_uri)
}

#[get("/upload/<token>", rank = 2)]
pub fn quick_upload_proceed(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    token: String,
) -> MyResponse {
    let result = vks::request_verify(
        db, token_stateful, token_stateless, mail_service,
        rate_limiter, token, vec!());
    MyResponse::upload_response(result)
}


#[post("/upload/submit", format = "application/x-www-form-urlencoded", data = "<data>")]
pub fn upload_post_form(
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
                return Ok(MyResponse::upload_response(vks::process_key(
                    &db,
                    &tokens_stateless,
                    &rate_limiter,
                    Cursor::new(decoded_value.as_bytes())
                )));
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
) -> Result<MyResponse> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(db, tokens_stateless, rate_limiter, entries)
        }
        Partial(partial, _) => {
            process_multipart(db, tokens_stateless, rate_limiter, partial.entries)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    entries: Entries,
) -> Result<MyResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            Ok(MyResponse::upload_response(vks::process_key(db, tokens_stateless, rate_limiter, reader)))
        }
        Some(_) =>
            Ok(MyResponse::bad_request(
                "upload/upload", failure::err_msg("Multiple keytexts found"))),
        None =>
            Ok(MyResponse::bad_request(
                "upload/upload", failure::err_msg("No keytext found"))),
    }
}

#[post("/upload/request-verify", format = "application/x-www-form-urlencoded", data="<request>")]
pub fn request_verify_form(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db, token_stateful, token_stateless, mail_service,
        rate_limiter, token, vec!(address));
    MyResponse::upload_response(result)
}

#[post("/upload/request-verify", format = "multipart/form-data", data="<request>")]
pub fn request_verify_form_data(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db, token_stateful, token_stateless, mail_service,
        rate_limiter, token, vec!(address));
    MyResponse::upload_response(result)
}

#[get("/verify/<token>")]
pub fn verify_confirm(
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<StatefulTokens>,
    token: String,
) -> MyResponse {
    match vks::verify_confirm(db, token_service, token) {
        PublishResponse::Ok { email } => {
            let context = template::Verify {
                verified: true,
                userid: email,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            MyResponse::ok("upload/publish-result", context)
        },
        PublishResponse::Error(error) => MyResponse::plain(error),
    }
}

