use rocket;
use rocket::response::content;

mod upload;

#[get("/key/<fpr>")]
fn key_by_fingerprint(fpr: String) -> String {
    format!("{}", fpr)
}

#[derive(FromForm)]
struct KeySubmissionForm {
    key: String,
}

#[post("/keys", data = "<data>")]
fn submit_key(data: String) -> String {
//use multipart::server::Multipart;
    //use openpgp::TPK;
    format!("{:?}", data)/*
    let strm = form.open();

    match TPK::from_reader(strm) {
        Ok(tpk) => {
            match tpk.userids().next() {
                Some(uid) => {
                    format!("Hello, {:?}", uid.userid())
                }
                None => {
                    format!("Hello, {:?}", tpk.primary().fingerprint())
                }
            }
        }
        Err(e) => {
            format!("Error: {:?}", e)
        }
    }*/
}

#[get("/")]
fn root() -> content::Html<&'static str> {
    content::Html("
<!doctype html>
<html>
    <head>
        <title>Garbage Pile Public Key Server</title>
    </head>

    <body>
        <h1>Garbage Pile Public Key Server</h1>
        <p>The verifying PGP key server. Powered by p&equiv;pnology!
        <h2>Search for keys</h2>
        <form action=\"/search\" method=POST>
            <input type=\"search\" id=\"query\" name=\"query\" placeholder=\"Email\">
            <input type=\"submit\" value=\"Search\">
        </form>
        <h2>Upload your key</h2>
        <form action=\"/keys\" method=POST enctype=multipart/form-data>
            <input type=\"file\" id=\"key\" name=\"key\" placeholder=\"Your public key\">
            <input type=\"submit\" value=\"Upload\">
        </form>
    </body>
</html>")
}

fn main() {
    rocket::ignite().mount("/", routes![
                           upload::multipart_upload,
                           key_by_fingerprint,
                           root]).launch();
}

//POST /keys
//GET /keys/<fpr>

