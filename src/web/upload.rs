use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::FlashMessage;
use rocket::response::Redirect;
use rocket::{Data, State};
use rocket_contrib::templates::Template;
use rocket::response::Flash;

use handlebars::Handlebars;

use database::{Database, Polymorphic};
use mail::send_verification_mail;
use web::{Domain, From, MailTemplates};

use std::io::Read;

mod template {
    #[derive(Serialize)]
    pub struct Upload {
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct VerificationError {
        pub error: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub emails: Vec<String>,
        pub commit: String,
        pub version: String,
    }
}

#[get("/upload")]
pub fn upload_landing(
    flash: Option<FlashMessage>
) -> Template {
    if let Some(flash) = flash {
        match flash.name() {
            "success" => {
                let emails: Vec<String> = serde_json::from_str(flash.msg()).unwrap();
                let context = template::VerificationSent {
                    emails: emails,
                    version: env!("VERGEN_SEMVER").to_string(),
                    commit: env!("VERGEN_SHA_SHORT").to_string(),
                };

                Template::render("upload_ok", context)
            }
            _ => show_error(flash.msg().to_owned())
        }
    } else {
        let context = template::Upload {
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
        };

        Template::render("upload", context)
    }
}

fn show_error(error: String) -> Template {
    let context = template::VerificationError {
        error,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Template::render("upload_err", context)
}

#[post("/upload/add", data = "<data>")]
pub fn upload_hkp(
    db: State<Polymorphic>, cont_type: &ContentType, data: Data,
    tmpl: State<MailTemplates>, domain: State<Domain>, from: State<From>
) -> Flash<Redirect> {
    match do_upload_hkp(db, cont_type, data, tmpl, domain, from) {
        Ok(ok) => ok,
        Err(err) => Flash::error(Redirect::to("/upload"), err.to_string()),
    }
}

// signature requires the request to have a `Content-Type`
pub fn do_upload_hkp(
    db: State<Polymorphic>, cont_type: &ContentType, data: Data,
    tmpl: State<MailTemplates>, domain: State<Domain>, from: State<From>,
) -> Result<Flash<Redirect>, String> {
    if cont_type.is_form_data() {
        // multipart/form-data
        let (_, boundary) = cont_type.params().find(|&(k, _)| k == "boundary").ok_or_else(
            || "`Content-Type: multipart/form-data` boundary param not provided".to_owned())?;

        process_upload(boundary, data, db.inner(), &tmpl.0, &domain.0, &from.0)
    } else if cont_type.is_form() {
        use rocket::request::FormItems;
        use std::io::Cursor;

        // application/x-www-form-urlencoded
        let mut buf = Vec::default();

        data.stream_to(&mut buf).or_else(|_| {
            Err("`Content-Type: application/x-www-form-urlencoded` not valid".to_owned())
        })?;

        for item in FormItems::from(&*String::from_utf8_lossy(&buf)) {
            let (key, value) = item.key_value();
            let decoded_value = value.url_decode().or_else(|_| {
                Err("`Content-Type: application/x-www-form-urlencoded` not valid".to_owned())
            })?;

            match key.as_str() {
                "keytext" => {
                    return process_key(
                        Cursor::new(decoded_value.as_bytes()),
                        &db,
                        &tmpl.0,
                        &domain.0,
                        &from.0,
                    );
                }
                _ => { /* skip */ }
            }
        }

        Err("Not a PGP public key".to_owned())
    } else {
        Err("Content-Type not a form".to_owned())
    }
}

fn process_upload(
    boundary: &str, data: Data, db: &Polymorphic, mail_templates: &Handlebars,
    domain: &str, from: &str,
) -> Result<Flash<Redirect>, String> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open(), boundary).save().temp() {
        Full(entries) => {
            process_multipart(entries, db, mail_templates, domain, from)
        }
        Partial(partial, _) => {
            process_multipart(partial.entries, db, mail_templates, domain, from)
        }
        Error(err) => Err(err.to_string())
    }
}

fn process_multipart(
    entries: Entries, db: &Polymorphic, mail_templates: &Handlebars,
    domain: &str, from: &str,
) -> Result<Flash<Redirect>, String> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable().map_err(|err| {
                err.to_string()
            })?;

            process_key(reader, db, mail_templates, domain, from)
        }
        Some(_) | None => {
            Err("Not a PGP public key".into())
        }
    }
}

fn process_key<R>(
    reader: R, db: &Polymorphic, mail_templates: &Handlebars, domain: &str,
    from: &str
) -> Result<Flash<Redirect>, String>
where
    R: Read,
{
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::TPK;

    let tpk = TPK::from_reader(reader).map_err(|err| err.to_string())?;
    let tokens = db.merge_or_publish(tpk)
        .map_err(|e| format!("{}", e))?;
    let mut results: Vec<String> = vec!();

    for (email,token) in tokens {
        send_verification_mail(
            &email,
            &token,
            mail_templates,
            domain,
            from,
        ).map_err(|e| format!("{}", e))?;
        results.push(email.to_string());
    }

    let json = serde_json::to_string(&results).unwrap();
    Ok(Flash::success(Redirect::to("/upload"), json))
}
