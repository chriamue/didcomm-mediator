#[macro_use]
extern crate rocket;
use base58::{FromBase58, ToBase58};
use did_key::{generate, DIDCore, Ed25519KeyPair, KeyMaterial, KeyPair, CONFIG_JOSE_PUBLIC};
use didcomm_rs::Message;
use rocket::{response::Redirect, serde::json::Json, State};

mod config;
mod invitation;
#[cfg(test)]
mod tests;

use config::Config;
use invitation::{Invitation, InvitationResponse};
use serde_json::Value;

#[get("/", rank = 3)]
fn index() -> Redirect {
    Redirect::to(uri!(invitation_endpoint))
}

#[get("/invitation")]
fn invitation_endpoint(config: &State<Config>, key: &State<KeyPair>) -> Json<InvitationResponse> {
    oob_invitation_endpoint(config, key)
}

#[post("/outofband/create-invitation")]
fn oob_invitation_endpoint(
    config: &State<Config>,
    key: &State<KeyPair>,
) -> Json<InvitationResponse> {
    let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
    let did = did_doc.id;

    let response = InvitationResponse {
        invitation: Invitation::new(
            did.to_string(),
            config.ident.to_string(),
            config.ext_service.to_string(),
        ),
    };

    Json(response)
}

#[post("/didcomm", format = "any", data = "<body>")]
fn didcomm_endpoint(key: &State<KeyPair>, body: Json<Value>) -> Json<Value> {
    let body_str = serde_json::to_string(&body.into_inner()).unwrap();

    #[cfg(test)]
    println!("{}", body_str);

    let received = Message::receive(&body_str, Some(&key.private_key_bytes()), None, None).unwrap();

    println!("received {}", received.as_raw_json().unwrap());
    Json(serde_json::from_str("{}").unwrap())
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("loading config");
    let key = match config.key_seed.clone() {
        Some(seed) => generate::<Ed25519KeyPair>(Some(&seed.from_base58().unwrap())),
        None => {
            let key = generate::<Ed25519KeyPair>(None);
            println!("Generated Seed: {}", key.private_key_bytes().to_base58());
            key
        }
    };
    let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
    let did = did_doc.id;
    config.did = did;

    rocket
        .mount(
            "/",
            routes![
                index,
                invitation_endpoint,
                didcomm_endpoint,
                oob_invitation_endpoint
            ],
        )
        .manage(config)
        .manage(key)
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use didcomm_rs::{
        crypto::{CryptoAlgorithm, SignatureAlgorithm},
        Message,
    };
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    #[test]
    fn test_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation_response: InvitationResponse = response.into_json().unwrap();
        assert_eq!(
            invitation_response.invitation.services[0].typ,
            "did-communication"
        );
    }

    #[test]
    fn test_oob_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.post("/outofband/create-invitation");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation_response: InvitationResponse = response.into_json().unwrap();
        assert_eq!(
            invitation_response.invitation.services[0].typ,
            "did-communication"
        );
    }

    #[test]
    fn test_didcomm_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation_response: InvitationResponse = response.into_json().unwrap();
        let invitation = invitation_response.invitation;
        let recipient_did = invitation.services[0].recipient_keys[0].to_string();
        let recipient_key = did_key::resolve(&recipient_did).unwrap();

        let key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let did = did_doc.id;

        let message = Message::new()
            .as_jwe(
                &CryptoAlgorithm::XC20P,
                Some(recipient_did.as_str().as_bytes().to_vec()),
            )
            .kid(&recipient_did);

        let ready_to_send = message
            .seal_signed(
                &key.private_key_bytes(),
                Some(vec![Some(recipient_did.as_str().as_bytes().to_vec())]),
                SignatureAlgorithm::EdDsa,
                &[key.private_key_bytes(), key.public_key_bytes()].concat(),
            )
            .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(ready_to_send);
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation_response: InvitationResponse = response.into_json().unwrap();
        assert_eq!(
            invitation_response.invitation.services[0].typ,
            "did-communication"
        );
    }
}
