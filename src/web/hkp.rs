use std::fmt;

use rocket::Data;
use rocket::Outcome;
use rocket::http::{ContentType, Status};
use rocket::request::{self, Request, FromRequest};

use database::{Database, Query, Polymorphic};
use database::types::{Email, Fingerprint, KeyID};

use web::{
    MyResponse,
    State,
    key_to_response,
    upload,
};

#[derive(Debug)]
pub enum Hkp {
    Fingerprint { fpr: Fingerprint, index: bool, machine_readable: bool },
    KeyID { keyid: KeyID, index: bool, machine_readable: bool },
    Email { email: Email, index: bool, machine_readable: bool },
    Invalid{ query: String, },
}

impl fmt::Display for Hkp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hkp::Fingerprint{ ref fpr,.. } => write!(f, "{}", fpr),
            Hkp::KeyID{ ref keyid,.. } => write!(f, "{}", keyid),
            Hkp::Email{ ref email,.. } => write!(f, "{}", email),
            Hkp::Invalid{ ref query } => write!(f, "{}", query),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for Hkp {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Hkp, ()> {
        use std::str::FromStr;
        use rocket::request::FormItems;
        use std::collections::HashMap;

        let query = request.uri().query().unwrap_or("");
        let fields = FormItems::from(query)
            .map(|item| {
                let (k, v) = item.key_value();

                let key = k.url_decode().unwrap_or_default();
                let value = v.url_decode().unwrap_or_default();
                (key, value)
            })
            .collect::<HashMap<_, _>>();

        if fields.contains_key("search")
            && fields
            .get("op")
            .map(|x| x == "get" || x == "index")
            .unwrap_or(false)
        {
            let index = fields.get("op").map(|x| x == "index").unwrap_or(false);
            let machine_readable =
                fields.get("options").map(|x| x.contains("mr"))
                .unwrap_or(false);
            let search = fields.get("search").cloned().unwrap_or_default();
            let maybe_fpr = Fingerprint::from_str(&search);
            let maybe_keyid = KeyID::from_str(&search);

            if let Ok(fpr) = maybe_fpr {
                Outcome::Success(Hkp::Fingerprint {
                    fpr: fpr,
                    index: index,
                    machine_readable: machine_readable,
                })
            } else if let Ok(keyid) = maybe_keyid {
                Outcome::Success(Hkp::KeyID {
                    keyid: keyid,
                    index: index,
                    machine_readable: machine_readable,
                })
            } else {
                match Email::from_str(&search) {
                    Ok(email) => {
                        Outcome::Success(Hkp::Email {
                            email: email,
                            index: index,
                            machine_readable: machine_readable,
                        })
                    }
                    Err(_) => {
                        Outcome::Success(Hkp::Invalid{
                            query: search
                        })
                    }
                }
            }
        } else if fields.get("op").map(|x| x == "vindex"
                                       || x.starts_with("x-"))
            .unwrap_or(false)
        {
            Outcome::Failure((Status::NotImplemented, ()))
        } else {
            Outcome::Failure((Status::BadRequest, ()))
        }
    }
}

#[post("/pks/add", data = "<data>")]
pub fn pks_add(db: rocket::State<Polymorphic>, cont_type: &ContentType, data: Data,
               state: rocket::State<State>)
               -> MyResponse {
    match upload::handle_upload(db, cont_type, data, None, state) {
        Ok(_) => MyResponse::plain("Ok".into()),
        Err(err) => MyResponse::ise(err),
    }
}

#[get("/pks/lookup")]
pub fn pks_lookup(state: rocket::State<State>,
                  db: rocket::State<Polymorphic>,
                  key: Hkp) -> MyResponse {
    let query_string = key.to_string();
    let (query, index, machine_readable) = match key {
        Hkp::Fingerprint { fpr, index, machine_readable } =>
            (Query::ByFingerprint(fpr), index, machine_readable),
        Hkp::KeyID { keyid, index, machine_readable } =>
            (Query::ByKeyID(keyid), index, machine_readable),
        Hkp::Email { email, index, machine_readable } => {
            (Query::ByEmail(email), index, machine_readable)
        }
        Hkp::Invalid { query: _ } => {
            return MyResponse::not_found(None, None);
        }
    };

    if index {
        key_to_hkp_index(db, query)
    } else {
        key_to_response(state, db, query_string, query, machine_readable)
    }
}

fn key_to_hkp_index<'a>(db: rocket::State<Polymorphic>, query: Query)
                        -> MyResponse {
    use sequoia_openpgp::RevocationStatus;

    let tpk = match db.lookup(&query) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => return MyResponse::not_found(None, None),
        Err(err) => { return MyResponse::ise(err); }
    };
    let mut out = String::default();
    let p = tpk.primary();

    let ctime = tpk
        .primary_key_signature()
        .and_then(|x| x.signature_creation_time())
        .map(|x| format!("{}", x.to_timespec().sec))
        .unwrap_or_default();
    let extime = tpk
        .primary_key_signature()
        .and_then(|x| x.signature_expiration_time())
        .map(|x| format!("{}", x))
        .unwrap_or_default();
    let is_exp = tpk
        .primary_key_signature()
        .and_then(|x| {
            if x.signature_expired() { "e" } else { "" }.into()
        })
    .unwrap_or_default();
    let is_rev =
        if tpk.revoked(None) != RevocationStatus::NotAsFarAsWeKnow {
            "r"
        } else {
            ""
        };
    let algo: u8 = p.pk_algo().into();

    out.push_str("info:1:1\r\n");
    out.push_str(&format!(
            "pub:{}:{}:{}:{}:{}:{}{}\r\n",
            p.fingerprint().to_string().replace(" ", ""),
            algo,
            p.mpis().bits(),
            ctime,
            extime,
            is_exp,
            is_rev
    ));

    for uid in tpk.userids() {
        let u =
            url::form_urlencoded::byte_serialize(uid.userid().userid())
            .fold(String::default(), |acc, x| acc + x);
        let ctime = uid
            .binding_signature()
            .and_then(|x| x.signature_creation_time())
            .map(|x| format!("{}", x.to_timespec().sec))
            .unwrap_or_default();
        let extime = uid
            .binding_signature()
            .and_then(|x| x.signature_expiration_time())
            .map(|x| format!("{}", x))
            .unwrap_or_default();
        let is_exp = uid
            .binding_signature()
            .and_then(|x| {
                if x.signature_expired() { "e" } else { "" }.into()
            })
        .unwrap_or_default();
        let is_rev = if uid.revoked(None)
            != RevocationStatus::NotAsFarAsWeKnow
            {
                "r"
            } else {
                ""
            };

        out.push_str(&format!(
                "uid:{}:{}:{}:{}{}\r\n",
                u, ctime, extime, is_exp, is_rev
        ));
    }

    MyResponse::plain(out)
}

#[cfg(test)]
mod tests {
    use rocket::http::Status;
    use rocket::http::ContentType;

    use sequoia_openpgp::tpk::TPKBuilder;
    use sequoia_openpgp::serialize::Serialize;

    use web::tests::*;

    #[test]
    fn hkp() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // eprintln!("LEAKING: {:?}", tmpdir);
        // ::std::mem::forget(tmpdir);

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap();

        // Prepare to /pks/add
        let mut armored = Vec::new();
        {
            use sequoia_openpgp::armor::{Writer, Kind};
            let mut w = Writer::new(&mut armored, Kind::PublicKey, &[])
                .unwrap();
            tpk.serialize(&mut w).unwrap();
        }
        let mut post_data = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored) {
            post_data.push_str(enc);
        }

        // Add!
        let mut response = client.post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.body_string().unwrap();
        eprintln!("response: {}", body);

        // Check that we do not get a confirmation mail.
        let confirm_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(confirm_mail.is_none());

        // We should not be able to look it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk);

        assert_consistency(client.rocket());
    }

    #[test]
    fn hkp_add_two() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate two keys and upload them.
        let tpk_0 = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap().0;
        let tpk_1 = TPKBuilder::autocrypt(
            None, Some("bar@invalid.example.com".into()))
            .generate().unwrap().0;

        // Prepare to /pks/add
        let mut armored = Vec::new();
        {
            use sequoia_openpgp::armor::{Writer, Kind};
            let mut w = Writer::new(&mut armored, Kind::PublicKey, &[])
                .unwrap();
            tpk_0.serialize(&mut w).unwrap();
            tpk_1.serialize(&mut w).unwrap();
        }
        let mut post_data = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored) {
            post_data.push_str(enc);
        }

        // Add!
        let response = client.post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let confirm_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(confirm_mail.is_none());
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_0);
        check_hr_responses_by_fingerprint(&client, &tpk_1);

        assert_consistency(client.rocket());
    }
}
