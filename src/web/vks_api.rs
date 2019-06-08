use rocket_contrib::json::{Json,JsonValue,JsonError};
use rocket::request::Request;
use rocket::response::{self, Response, Responder};
use rocket::http::{ContentType,Status};
use std::io::Cursor;

use database::{KeyDatabase, StatefulTokens};
use mail;
use tokens;
use rate_limiter::RateLimiter;

use web::HagridState;
use web::vks;
use web::vks::response::*;

pub mod json {
    use web::vks::response::EmailStatus;
    use std::collections::HashMap;

    #[derive(Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub addresses: Vec<String>,
    }

    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }

    #[derive(Serialize,Deserialize)]
    pub struct UploadResult {
        pub token: String,
        pub key_fpr: String,
        pub status: HashMap<String,EmailStatus>,
    }
}

type JsonResult = Result<JsonValue, JsonErrorResponse>;

#[derive(Debug)]
pub struct JsonErrorResponse(Status,String);

impl<'r> Responder<'r> for JsonErrorResponse {
    fn respond_to(self, _: &Request) -> response::Result<'r> {
        let error_json = json!({"error": self.1});
        Response::build()
            .status(self.0)
            .sized_body(Cursor::new(error_json.to_string()))
            .header(ContentType::JSON)
            .ok()
    }
}

fn json_or_error<T>(data: Result<Json<T>, JsonError>) -> Result<Json<T>, JsonErrorResponse> {
    match data {
        Ok(data) => Ok(data),
        Err(JsonError::Io(_)) => Err(JsonErrorResponse(Status::InternalServerError, "i/o error!".to_owned())),
        Err(JsonError::Parse(_, e)) => Err(JsonErrorResponse(Status::BadRequest, e.to_string())),
    }
}

fn upload_ok_json(response: UploadResponse) -> Result<JsonValue,JsonErrorResponse> {
    match response {
        UploadResponse::Ok { token, key_fpr, status, .. } =>
            Ok(json!(json::UploadResult { token, key_fpr, status })),
        UploadResponse::OkMulti { key_fprs } => Ok(json!(key_fprs)),
        UploadResponse::Error(error) => Err(JsonErrorResponse(Status::BadRequest, error)),
    }
}

#[post("/vks/v1/upload", format = "json", data = "<data>")]
pub fn upload_json(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    data: Result<Json<json::UploadRequest>, JsonError>,
) -> JsonResult {
    let data = json_or_error(data)?;
    use std::io::Cursor;
    let data_reader = Cursor::new(data.keytext.as_bytes());
    let result = vks::process_key(&db, &tokens_stateless, &rate_limiter, data_reader);
    upload_ok_json(result)
}

#[post("/vks/v1/upload", rank = 2)]
pub fn upload_fallback(
    state: rocket::State<HagridState>,
) -> JsonErrorResponse {
    let error_msg = format!("expected application/json data. see {}/about/api for api docs.", state.base_uri);
    JsonErrorResponse(Status::BadRequest, error_msg)
}

#[post("/vks/v1/request-verify", format = "json", data="<data>")]
pub fn request_verify_json(
    db: rocket::State<KeyDatabase>,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    data: Result<Json<json::VerifyRequest>, JsonError>,
) -> JsonResult {
    let data = json_or_error(data)?;
    let json::VerifyRequest { token, addresses } = data.into_inner();
    let result = vks::request_verify(
        db, token_stateful, token_stateless, mail_service,
        rate_limiter, token, addresses);
    upload_ok_json(result)
}

#[post("/vks/v1/request-verify", rank = 2)]
pub fn request_verify_fallback(
    state: rocket::State<HagridState>,
) -> JsonErrorResponse {
    let error_msg = format!("expected application/json data. see {}/about/api for api docs.", state.base_uri);
    JsonErrorResponse(Status::BadRequest, error_msg)
}
