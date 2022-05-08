#[macro_use]
extern crate rocket;
use did_key::{generate, DIDCore, Ed25519KeyPair, KeyPair, CONFIG_JOSE_PUBLIC};
use rocket::{response::Redirect, serde::json::Json, State};

mod config;
mod invitation;

use config::Config;
use invitation::Invitation;

#[get("/", rank = 3)]
fn index() -> Redirect {
    Redirect::to(uri!(invitation_endpoint))
}

#[get("/invitation")]
fn invitation_endpoint(config: &State<Config>, key: &State<KeyPair>) -> Json<Invitation> {
    let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
    let did = did_doc.id;

    Json(Invitation::new(
        did.to_string(),
        config.ident.to_string(),
        config.ext_service.to_string(),
    ))
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("loading config");
    let key = generate::<Ed25519KeyPair>(Some(config.key_seed.as_str().as_bytes()));
    let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
    let did = did_doc.id;
    config.did = did;

    rocket
        .mount("/", routes![index, invitation_endpoint])
        .manage(config)
        .manage(key)
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
        let req = client.get("/invitation");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation: Invitation = response.into_json().unwrap();
        assert_eq!(invitation.services[0].typ, "did-communication");
    }
}
