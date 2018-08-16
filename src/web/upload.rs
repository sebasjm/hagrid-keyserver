use multipart::server::Multipart;
use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;

use rocket::Data;
use rocket::http::{ContentType, Status};
use rocket::response::status::Custom;

#[post("/keys", data = "<data>")]
// signature requires the request to have a `Content-Type`
pub fn multipart_upload(cont_type: &ContentType, data: Data) -> Result<String, Custom<String>> {
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

    process_upload(boundary, data)
}

fn process_upload(boundary: &str, data: Data) -> Result<String, Custom<String>> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open(), boundary).save().temp() {
        Full(entries) => process_entries(entries),
        Partial(partial, _) => {
            process_entries(partial.entries)
        },
        Error(err) => Err(Custom(Status::InternalServerError, err.to_string())),
    }
}

// having a streaming output would be nice; there's one for returning a `Read` impl
// but not one that you can `write()` to
fn process_entries(entries: Entries) -> Result<String, Custom<String>> {
    use openpgp::TPK;

    match entries.fields.get(&"key".to_string()) {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable().map_err(|err| {
                Custom(Status::InternalServerError, err.to_string())
            })?;

            match TPK::from_reader(reader) {
                Ok(tpk) => {
                    match tpk.userids().next() {
                        Some(uid) => {
                            Ok(format!("Hello, {:?}", uid.userid()))
                        }
                        None => {
                            Ok(format!("Hello, {:?}", tpk.primary().fingerprint()))
                        }
                    }
                }
                Err(e) => {
                    Ok(format!("Error: {:?}", e))
                }
            }
        }
        Some(_) | None => Err(Custom(
            Status::BadRequest,
            "Not a PGP public key".into()
        )),
    }
}

