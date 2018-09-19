use multipart::server::Multipart;
use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;

use rocket::{State, Data};
use rocket::http::{ContentType, Status};
use rocket::response::status::Custom;
use rocket_contrib::Template;

use database::{Database, Polymorphic};

mod template {
    #[derive(Serialize)]
    pub struct Token {
        pub userid: String,
        pub token: String,
    }

    #[derive(Serialize)]
    pub struct Context {
        pub tokens: Vec<Token>,
    }
}

#[post("/keys", data = "<data>")]
// signature requires the request to have a `Content-Type`
pub fn multipart_upload(db: State<Polymorphic>, cont_type: &ContentType, data: Data) -> Result<Template, Custom<String>> {
    // this and the next check can be implemented as a request guard but it seems like just
    // more boilerplate than necessary
    if !cont_type.is_form_data() {
        return Err(Custom(
            Status::BadRequest,
            "Content-Type not multipart/form-data".into()
        ));
    }

    let (_, boundary) = cont_type.params().find(|&(k, _)| k == "boundary").ok_or_else(
            || Custom(
                Status::BadRequest,
                "`Content-Type: multipart/form-data` boundary param not provided".into()
            )
        )?;

    process_upload(boundary, data, db.inner())
}

fn process_upload(boundary: &str, data: Data, db: &Polymorphic) -> Result<Template, Custom<String>> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open(), boundary).save().temp() {
        Full(entries) => process_entries(entries, db),
        Partial(partial, _) => {
            process_entries(partial.entries, db)
        },
        Error(err) => Err(Custom(Status::InternalServerError, err.to_string())),
    }
}

// having a streaming output would be nice; there's one for returning a `Read` impl
// but not one that you can `write()` to
fn process_entries(entries: Entries, db: &Polymorphic) -> Result<Template, Custom<String>> {
    use openpgp::TPK;

    match entries.fields.get(&"key".to_string()) {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable().map_err(|err| {
                Custom(Status::InternalServerError, err.to_string())
            })?;

            match TPK::from_reader(reader) {
                Ok(tpk) => {
                    match db.merge_or_publish(tpk) {
                        Ok(tokens) => {
                            let tokens = tokens
                                .into_iter().map(|(uid,tok)| {
                                    template::Token{ userid: uid.to_string(), token: tok }
                                }).collect::<Vec<_>>();
                            let context = template::Context{
                                tokens: tokens
                            };

                            Ok(Template::render("upload", context))
                        }
                        Err(err) =>
                            Err(Custom(Status::InternalServerError,
                                       format!("{:?}", err))),
                    }
                }
                Err(_) => Err(Custom(Status::BadRequest,
                                     "Not a PGP public key".into())),
            }
        }
        Some(_) | None =>
            Err(Custom(Status::BadRequest, "Not a PGP public key".into())),
    }
}

