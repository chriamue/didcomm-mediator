#[macro_use]
extern crate rocket;
use base58::{FromBase58, ToBase58};
use did_key::{
    generate, DIDCore, KeyMaterial, KeyPair, X25519KeyPair, CONFIG_JOSE_PUBLIC, CONFIG_LD_PUBLIC,
};
use didcomm_mediator::config::Config;
use didcomm_mediator::connections::Connections;
use didcomm_mediator::handler::{DidcommHandler, HandlerResponse};
use didcomm_mediator::invitation::{Invitation, InvitationResponse};
use didcomm_mediator::protocols::didexchange::DidExchangeHandler;
use didcomm_mediator::protocols::discoverfeatures::DiscoverFeaturesHandler;
use didcomm_mediator::protocols::messagepickup::MessagePickupHandler;
use didcomm_mediator::protocols::trustping::TrustPingHandler;
use didcomm_rs::Message;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{response::Redirect, serde::json::Json, State};
use rocket::{Request, Response};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::vec;

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
            did,
            config.ident.to_string(),
            config.ext_service.to_string(),
        ),
    };

    Json(response)
}

#[get("/.well-known/did.json")]
fn did_web_endpoint(config: &State<Config>, key: &State<KeyPair>) -> Json<Value> {
    let mut did_doc = key.get_did_document(CONFIG_LD_PUBLIC);
    did_doc.verification_method[0].private_key = None;
    let mut did_doc = serde_json::to_value(&did_doc).unwrap();
    did_doc["service"] = serde_json::json!([
      {
        "id": "2e9e814a-c1e1-416e-a21a-a4182809950c",
        "serviceEndpoint": config.ext_service,
        "type": "did-communication"
      }
    ]);
    Json(did_doc)
}

#[post("/didcomm", format = "any", data = "<body>")]
fn didcomm_endpoint(
    key: &State<KeyPair>,
    connections: &State<Arc<Mutex<Connections>>>,
    body: Json<Value>,
) -> Json<Value> {
    let body_str = serde_json::to_string(&body.into_inner()).unwrap();

    #[cfg(test)]
    println!("{}", body_str);

    let received = Message::receive(&body_str, Some(&key.private_key_bytes()), None, None).unwrap();

    let handlers: Vec<Box<dyn DidcommHandler>> = vec![
        Box::new(DidExchangeHandler::default()),
        Box::new(DiscoverFeaturesHandler::default()),
        Box::new(TrustPingHandler::default()),
        Box::new(MessagePickupHandler::default()),
    ];

    let mut response: Value = serde_json::json!({});
    for handler in handlers {
        let connection_locked = connections.try_lock().unwrap();
        match handler.handle(&received, Some(key), Some(&connection_locked)) {
            HandlerResponse::Skipped => {}
            HandlerResponse::Processed => {
                break;
            }
            HandlerResponse::Response(product) => {
                response = product;
                break;
            }
        }
    }

    Json(response)
}

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("loading config");
    let key = match config.key_seed.clone() {
        Some(seed) => generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap())),
        None => {
            let key = generate::<X25519KeyPair>(None);
            println!("Generated Seed: {}", key.private_key_bytes().to_base58());
            key
        }
    };
    let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
    let did = did_doc.id.to_string();

    println!("{}", did);

    config.did = did;

    let connections = Arc::new(Mutex::new(Connections::new()));

    rocket
        .attach(CORS)
        .mount(
            "/",
            routes![
                index,
                invitation_endpoint,
                didcomm_endpoint,
                oob_invitation_endpoint,
                did_web_endpoint
            ],
        )
        .manage(config)
        .manage(key)
        .manage(connections)
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use did_key::Ed25519KeyPair;
    use didcomm_mediator::protocols::trustping::TrustPingResponseBuilder;
    use didcomm_rs::crypto::{CryptoAlgorithm, SignatureAlgorithm};
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

        let key = generate::<X25519KeyPair>(None);
        let sign_key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let did_from = did_doc.id;

        let body = r#"{"foo":"bar"}"#;
        let message = Message::new()
            .from(&did_from)
            .to(&[&recipient_did])
            .body(body)
            .as_jwe(
                &CryptoAlgorithm::XC20P,
                Some(recipient_key.public_key_bytes()),
            )
            .kid(&hex::encode(sign_key.public_key_bytes()));

        let ready_to_send = message
            .seal_signed(
                &key.private_key_bytes(),
                Some(vec![Some(recipient_key.public_key_bytes())]),
                SignatureAlgorithm::EdDsa,
                &[sign_key.private_key_bytes(), sign_key.public_key_bytes()].concat(),
            )
            .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(ready_to_send);
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_trust_ping() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation_response: InvitationResponse = response.into_json().unwrap();
        let invitation = invitation_response.invitation;
        let recipient_did = invitation.services[0].recipient_keys[0].to_string();
        let recipient_key = did_key::resolve(&recipient_did).unwrap();

        let key = generate::<X25519KeyPair>(None);
        let sign_key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let did_from = did_doc.id;

        let message = TrustPingResponseBuilder::new()
            .build()
            .unwrap()
            .from(&did_from)
            .to(&[&recipient_did])
            .as_jwe(
                &CryptoAlgorithm::XC20P,
                Some(recipient_key.public_key_bytes()),
            )
            .kid(&hex::encode(sign_key.public_key_bytes()));

        let ready_to_send = message
            .seal_signed(
                &key.private_key_bytes(),
                Some(vec![Some(recipient_key.public_key_bytes())]),
                SignatureAlgorithm::EdDsa,
                &[sign_key.private_key_bytes(), sign_key.public_key_bytes()].concat(),
            )
            .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(ready_to_send);
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response_json = response.into_string().unwrap();
        println!("response {}", response_json);
        let received = Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);

        assert!(&received.is_ok());
    }
}
