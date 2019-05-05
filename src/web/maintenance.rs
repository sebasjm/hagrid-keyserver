use rocket::{Request, Data};
use rocket::fairing::{Fairing, Info, Kind};
use rocket_contrib::templates::Template;
use rocket::http::Method;

use std::fs;
use std::path::PathBuf;

use web::MyResponse;

pub struct MaintenanceMode {
    maintenance_file: PathBuf,
}

mod templates {
    #[derive(Serialize)]
    pub struct MaintenanceMode {
        pub message: String,
        pub commit: String,
        pub version: String,
    }
}

impl Fairing for MaintenanceMode {
    fn info(&self) -> Info {
        Info {
            name: "Maintenance Mode",
            kind: Kind::Request
        }
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        if !self.is_relevant_path(request.uri().path()) { 
            return;
        }
        if let Some(message) = self.get_maintenance_message() {
            request.set_uri(uri!(maintenance_error: message));
            request.set_method(Method::Get);
        }
    }
}

impl MaintenanceMode {
    pub fn new(maintenance_file: PathBuf) -> Self {
        MaintenanceMode { maintenance_file }
    }

    fn is_relevant_path(&self, path: &str) -> bool {
        path.starts_with("/publish") || path.starts_with("/manage")
    }

    fn get_maintenance_message(&self) -> Option<String> {
        if !self.maintenance_file.exists() {
            return None;
        }
        fs::read_to_string(&self.maintenance_file).ok()
    }
}

#[get("/maintenance/<message>")]
pub fn maintenance_error(message: String) -> MyResponse {
    let ctx = templates::MaintenanceMode{
        message,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };
    MyResponse::ServerError(Template::render("maintenance", ctx))
}
