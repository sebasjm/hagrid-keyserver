use multipart::server::Multipart;
use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;

use rocket::{State, Data};
use rocket::http::{ContentType, Status};
use rocket::response::status::Custom;
use rocket_contrib::templates::Template;

use types::Email;
use mail::send_verification_mail;
use web::{Domain, MailTemplateDir};
use database::{Database, Polymorphic};

use std::io::Read;
use std::str::FromStr;

mod template {
    #[derive(Serialize)]
    pub struct Token {
        pub userid: String,
        pub token: String,
    }

    #[derive(Serialize)]
    pub struct Verify {
        pub tokens: Vec<Token>,
    }
}

#[post("/pks/add", data = "<data>")]
// signature requires the request to have a `Content-Type`
pub fn multipart_upload(db: State<Polymorphic>, cont_type: &ContentType,
                        data: Data, tmpl: State<MailTemplateDir>,
                        domain: State<Domain>)
    -> Result<Template, Custom<String>>
{
    if cont_type.is_form_data() {
        // multipart/form-data
        let (_, boundary) = cont_type.params().find(|&(k, _)| k == "boundary").ok_or_else(
            || Custom(
                Status::BadRequest,
                "`Content-Type: multipart/form-data` boundary param not provided".into()
                )
            )?;

        process_upload(boundary, data, db.inner(), &(tmpl.0)[..], &(domain.0)[..])
    } else if cont_type.is_form() {
        use rocket::request::FormItems;
        use std::io::Cursor;

        // application/x-www-form-urlencoded
        let mut buf = Vec::default();

        data.stream_to(&mut buf).or_else(|_| {
            Err(Custom(Status::BadRequest,
                       "`Content-Type: application/x-www-form-urlencoded` not valid".into()))
        })?;

        for item in FormItems::from(&*String::from_utf8_lossy(&buf)) {
            let (key, value) = item.key_value();
            let decoded_value = value.url_decode().or_else(|_| {
                Err(Custom(Status::BadRequest,
                           "`Content-Type: application/x-www-form-urlencoded` not valid".into()))
            })?;

            match key.as_str() {
                "keytext" => {
                    return process_key(Cursor::new(decoded_value.as_bytes()),
                                       &db, &(tmpl.0)[..], &(domain.0)[..]);
                }
                _ => { /* skip */ }
            }
        }

        Err(Custom(Status::BadRequest, "Not a PGP public key".into()))
    } else {
        Err(Custom(Status::BadRequest, "Content-Type not a form".into()))
    }
}

fn process_upload(boundary: &str, data: Data, db: &Polymorphic, tmpl: &str,
                  domain: &str)
    -> Result<Template, Custom<String>>
{
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open(), boundary).save().temp() {
        Full(entries) => process_multipart(entries, db, tmpl, domain),
        Partial(partial, _) => process_multipart(partial.entries, db, tmpl, domain),
        Error(err) => Err(Custom(Status::InternalServerError, err.to_string())),
    }
}

fn process_multipart(entries: Entries, db: &Polymorphic, tmpl: &str,
                     domain: &str)
    -> Result<Template, Custom<String>>
{
    match entries.fields.get(&"keytext".to_string()) {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable().map_err(|err| {
                Custom(Status::InternalServerError, err.to_string())
            })?;

            process_key(reader, db, tmpl, domain)
        }
        Some(_) | None =>
            Err(Custom(Status::BadRequest, "Not a PGP public key".into())),
    }
}

fn process_key<R>(reader: R, db: &Polymorphic, tmpl: &str, domain: &str)
    -> Result<Template, Custom<String>> where R: Read
{
    use sequoia_openpgp::TPK;
    use sequoia_openpgp::parse::Parse;

    match TPK::from_reader(reader) {
        Ok(tpk) => {
            match db.merge_or_publish(tpk) {
                Ok(tokens) => {
                    let tokens = tokens
                        .into_iter().map(|(uid,tok)| {
                            template::Token{ userid: uid.to_string(), token: tok }
                        }).collect::<Vec<_>>();

                    // send out emails
                    for tok in tokens.iter() {
                        let &template::Token{ ref userid, ref token } = tok;

                        Email::from_str(userid).and_then(|email| {
                            send_verification_mail(&email, token, tmpl, domain)
                        }).map_err(|err| {
                            Custom(Status::InternalServerError, format!("{:?}", err))
                        })?;
                    }

                    let context = template::Verify{
                        tokens: tokens
                    };

                    Ok(Template::render("upload", context))
                }
                Err(err) =>
                    Err(Custom(Status::InternalServerError,
                               format!("{:?}", err))),
            }
        }
        Err(_) => Err(Custom(Status::BadRequest, "Not a PGP public key".into())),
    }
}
