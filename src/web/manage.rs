use rocket;
use rocket::State;
use rocket::request::Form;

use failure::Fallible as Result;

use web::{HagridState, MyResponse, templates::General};
use database::{Database, KeyDatabase, types::Email};
use mail;
use tokens;

mod templates {
    #[derive(Serialize)]
    pub struct ManageKey {
        pub key_fpr: String,
        pub key_link: String,
        pub base_uri: String,
        pub uid_status: Vec<ManageKeyUidStatus>,
        pub token: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct ManageLinkSent {
        pub address: String,
    }

    #[derive(Serialize)]
    pub struct ManageKeyUidStatus {
       pub address: String,
       pub published: bool,
    }
}

pub mod forms {
    #[derive(FromForm)]
    pub struct ManageRequest {
        pub search_term: String,
    }

    #[derive(FromForm)]
    pub struct ManageDelete {
        pub token: String,
        pub address: String,
    }
}

#[get("/manage")]
pub fn vks_manage() -> Result<MyResponse> {
    Ok(MyResponse::ok("manage/manage", General::default()))
}

#[get("/manage/<token>")]
pub fn vks_manage_key(
   state: rocket::State<HagridState>,
   db: State<KeyDatabase>,
   token: String,
   token_service: rocket::State<tokens::Service>,
) -> MyResponse {
    use database::types::Fingerprint;
    use std::convert::TryFrom;
    if let Ok(fingerprint) = token_service.check(&token) {
        match db.lookup(&database::Query::ByFingerprint(fingerprint)) {
            Ok(Some(tpk)) => {
                let fp = Fingerprint::try_from(tpk.fingerprint()).unwrap();
                let mut emails: Vec<Email> = tpk.userids()
                    .map(|u| u.userid().to_string().parse::<Email>())
                    .flatten()
                    .collect();
                emails.sort_unstable();
                emails.dedup();
                let uid_status = emails.into_iter().map(|email|
                    templates::ManageKeyUidStatus {
                        address: email.to_string(),
                        published: true,
                    }
                ).collect();
                use web::get_link_by_fingerprint;
                let context = templates::ManageKey {
                    key_fpr: fp.to_string(),
                    key_link: get_link_by_fingerprint(&fp),
                    uid_status,
                    token,
                    base_uri: state.base_uri.clone(),
                    version: env!("VERGEN_SEMVER").to_string(),
                    commit: env!("VERGEN_SHA_SHORT").to_string(),
                };
                MyResponse::ok("manage/manage_key", context)
            },
            Ok(None) => MyResponse::not_found(
                Some("manage/manage"),
                Some("This link is invalid or expired".to_owned())),
            Err(e) => MyResponse::ise(e),
        }
    } else {
        MyResponse::ok("manage/manage_expired", General::default())
    }
}

#[post("/manage", data="<request>")]
pub fn vks_manage_post(
    db: State<KeyDatabase>,
    request: Form<forms::ManageRequest>,
    token_service: rocket::State<tokens::Service>,
    mail_service: Option<rocket::State<mail::Service>>,
) -> MyResponse {
    use std::convert::TryInto;

    let email = match request.search_term.parse::<Email>() {
        Ok(email) => email,
        Err(_) => return MyResponse::not_found(
            Some("manage/manage"),
            Some(format!("Malformed email address: {:?}", request.search_term)))
    };

    let tpk = match db.lookup(&database::Query::ByEmail(email.clone())) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => return MyResponse::not_found(
            Some("manage/manage"),
            Some(format!("No key for address {:?}", request.search_term))),
        Err(e) => return MyResponse::ise(e),
    };

    let fpr = tpk.fingerprint().try_into().unwrap();
    let token = token_service.create(&fpr);
    let token_uri = uri!(vks_manage_key: token).to_string();
    if let Some(mail_service) = mail_service {
      for binding in tpk.userids() {
         let email_candidate = binding.userid().to_string().parse::<Email>();
         if let Ok(email_candidate) = email_candidate {
            if &email_candidate != &email {
               continue;
            }
            if let Err(e) = mail_service.send_manage_token(
               &[email_candidate], &token_uri) {
               return MyResponse::ise(e);
            }
         }
      }
    }
    let ctx = templates::ManageLinkSent {
        address: email.to_string(),
    };
    MyResponse::ok("manage/manage_link_sent", ctx)
}

#[post("/manage/unpublish", data="<request>")]
pub fn vks_manage_unpublish(
    state: rocket::State<HagridState>,
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<tokens::Service>,
    request: Form<forms::ManageDelete>,
) -> MyResponse {
    match vks_manage_unpublish_or_fail(state, db, token_service, request) {
        Ok(response) => response,
        Err(e) => MyResponse::ise(e),
    }
}

pub fn vks_manage_unpublish_or_fail(
    state: rocket::State<HagridState>,
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<tokens::Service>,
    request: Form<forms::ManageDelete>,
) -> Result<MyResponse> {
    let fpr = token_service.check(&request.token)?;
    let email = request.address.parse::<Email>()?;
    db.delete_userids_matching(&fpr, &email)?;
    Ok(vks_manage_key(state, db, request.token.to_owned(), token_service))
}
