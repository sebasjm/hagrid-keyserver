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
        let message = match self.get_maintenance_message() {
            Some(message) => message,
            None => return,
        };

        let path = request.uri().path();
        if self.is_relevant_path_api(path) || request.method() == Method::Put {
            request.set_uri(uri!(maintenance_error_api: message));
            request.set_method(Method::Get);
        } else if self.is_relevant_path_web(path) {
            request.set_uri(uri!(maintenance_error_web: message));
            request.set_method(Method::Get);
        }
    }
}

impl MaintenanceMode {
    pub fn new(maintenance_file: PathBuf) -> Self {
        MaintenanceMode { maintenance_file }
    }

    fn is_relevant_path_api(&self, path: &str) -> bool {
        path.starts_with("/vks/v1/upload") ||
            path.starts_with("/pks/add")
    }

    fn is_relevant_path_web(&self, path: &str) -> bool {
        path.starts_with("/upload") ||
            path.starts_with("/manage") ||
            path.starts_with("/verify")
    }

    fn get_maintenance_message(&self) -> Option<String> {
        if !self.maintenance_file.exists() {
            return None;
        }
        fs::read_to_string(&self.maintenance_file).ok()
    }
}

#[get("/maintenance/api/<message>")]
pub fn maintenance_error_api(message: String) -> MyResponse {
    MyResponse::MaintenancePlain(message)
}

#[get("/maintenance/web/<message>")]
pub fn maintenance_error_web(message: String) -> MyResponse {
    let ctx = templates::MaintenanceMode{
        message,
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };
    MyResponse::Maintenance(Template::render("maintenance", ctx))
}
