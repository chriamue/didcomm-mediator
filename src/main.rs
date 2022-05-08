#[macro_use]
extern crate rocket;
use rocket::{serde::json::Json, State};

mod config;
mod invitation;

use config::Config;
use invitation::Invitation;

#[get("/")]
fn index(config: &State<Config>) -> Json<Invitation> {
    Json(Invitation::new(
        config.did.to_string(),
        config.ident.to_string(),
        config.ext_service.to_string(),
    ))
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let config: Config = figment.extract().expect("config");

    rocket.mount("/", routes![index]).manage(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rocket::http::Status;
    use rocket::local::blocking::Client;

    #[test]
    fn test_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation: Invitation = response.into_json().unwrap();
        assert_eq!(invitation.services[0].typ, "did-communication");
    }
}
