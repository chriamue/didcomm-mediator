#[macro_use]
extern crate rocket;
use async_mutex::Mutex;
use base58::{FromBase58, ToBase58};
use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair, CONFIG_LD_PUBLIC};
use didcomm_mediator::config::Config;
use didcomm_mediator::connections::{ConnectionStorage, Connections};
use didcomm_mediator::diddoc::DidDocBuilder;
use didcomm_mediator::didweb::url_to_did_web;
use didcomm_mediator::handler::{DidcommHandler, HandlerResponse};
use didcomm_mediator::message::receive;
use didcomm_mediator::message::{has_return_route_all_header, sign_and_encrypt};
use didcomm_mediator::protocols::didexchange::{DidExchangeHandler, DidExchangeResponseBuilder};
use didcomm_mediator::protocols::discoverfeatures::DiscoverFeaturesHandler;
use didcomm_mediator::protocols::forward::{ForwardBuilder, ForwardHandler};
use didcomm_mediator::protocols::invitation::InvitationBuilder;
use didcomm_mediator::protocols::messagepickup::MessagePickupHandler;
use didcomm_mediator::protocols::trustping::TrustPingHandler;
use didcomm_mediator::service::Service;
use didcomm_mediator::wallet::Wallet;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::{response::Redirect, serde::json::Json, Request, Response, State};
use serde_json::Value;
use std::sync::Arc;
use std::vec;

#[get("/", rank = 3)]
fn index() -> Redirect {
    Redirect::to(uri!(invitation_endpoint))
}

#[get("/invitation")]
async fn invitation_endpoint(config: &State<Config>, wallet: &State<Wallet>) -> Json<Value> {
    oob_invitation_endpoint(config, wallet).await
}

#[post("/outofband/create-invitation")]
async fn oob_invitation_endpoint(config: &State<Config>, wallet: &State<Wallet>) -> Json<Value> {
    let mut did_doc = wallet.keypair().get_did_document(CONFIG_LD_PUBLIC);
    did_doc.verification_method[0].private_key = None;

    let did_exchange = DidExchangeResponseBuilder::new()
        .did_doc(serde_json::to_value(&did_doc).unwrap())
        .did(wallet.did_key())
        .build_request()
        .unwrap();

    let mut services: Vec<Service> =
        vec![
            Service::new(wallet.did_key(), config.ext_service.to_string())
                .await
                .unwrap(),
        ];
    #[cfg(feature = "iota")]
    services.push(
        Service::new(wallet.did_iota().unwrap(), config.ext_service.to_string())
            .await
            .unwrap(),
    );
    let invitation = InvitationBuilder::new()
        .goal("to create a relationship".to_string())
        .goal_code("aries.rel.build".to_string())
        .services(services)
        .attachments(vec![did_exchange])
        .build()
        .unwrap();

    let response = serde_json::from_str(&invitation.as_raw_json().unwrap()).unwrap();
    Json(response)
}

#[get("/.well-known/did.json")]
async fn did_web_endpoint(config: &State<Config>, wallet: &State<Wallet>) -> Json<Value> {
    let ext_hostname = config.ext_hostname.to_string();
    let did_web = url_to_did_web(&ext_hostname);

    let mut did_doc_builder = DidDocBuilder::new();
    did_doc_builder
        .did(did_web)
        .endpoint(config.ext_service.to_string())
        .keypair(wallet.keypair());

    #[cfg(feature = "iota")]
    {
        use identity_iota::client::ResolvedIotaDocument;
        use identity_iota::client::Resolver;
        use identity_iota::iota_core::IotaDID;
        use std::str::FromStr;
        let did = IotaDID::from_str(config.did_iota.as_ref().unwrap()).unwrap();

        let resolver: Resolver = Resolver::new().await.unwrap();
        let resolved_did_document: ResolvedIotaDocument = resolver.resolve(&did).await.unwrap();

        let document = resolved_did_document.document;
        did_doc_builder.iota_document(document);
    }

    let did_doc = did_doc_builder.build().unwrap();
    Json(did_doc)
}

#[options("/didcomm")]
fn didcomm_options() -> Status {
    Status::Ok
}

#[post("/", format = "any", data = "<body>")]
async fn root_didcomm_endpoint(
    wallet: &State<Wallet>,
    connections: &State<Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    body: Json<Value>,
) -> Result<Json<Value>, Status> {
    didcomm_endpoint(wallet, connections, body).await
}

#[post("/didcomm", format = "any", data = "<body>")]
async fn didcomm_endpoint(
    wallet: &State<Wallet>,
    connections: &State<Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    body: Json<Value>,
) -> Result<Json<Value>, Status> {
    let body_str = serde_json::to_string(&body.into_inner()).unwrap();
    let connections: &Arc<Mutex<Box<dyn ConnectionStorage>>> = connections;

    let received = match receive(
        &body_str,
        Some(&wallet.keypair().private_key_bytes()),
        None,
        None,
    )
    .await
    {
        Ok(received) => received,
        Err(_) => return Err(Status::BadRequest),
    };

    let handlers: Vec<Box<dyn DidcommHandler>> = vec![
        Box::new(ForwardHandler::default()),
        Box::new(DidExchangeHandler::default()),
        Box::new(DiscoverFeaturesHandler::default()),
        Box::new(TrustPingHandler::default()),
        Box::new(MessagePickupHandler::default()),
    ];

    for handler in handlers {
        let handled = {
            let connections = connections.clone();
            let handled = handler
                .handle(&received, Some(&wallet.keypair()), Some(&connections))
                .await;
            handled.unwrap()
        };
        match handled {
            HandlerResponse::Skipped => {}
            HandlerResponse::Processed => {}
            HandlerResponse::Forward(receivers, message) => {
                for receiver in receivers {
                    let forward = ForwardBuilder::new()
                        .did(receiver.to_string())
                        .message(serde_json::to_string(&message).unwrap())
                        .build()
                        .unwrap();
                    let mut locked_connections = connections.try_lock().unwrap();
                    locked_connections
                        .insert_message_for(forward, receiver.to_string())
                        .await;
                    drop(locked_connections);
                }
            }
            HandlerResponse::Send(to, message) => match has_return_route_all_header(&received) {
                true => {
                    let response = match sign_and_encrypt(
                        &message,
                        &wallet.keypair().get_did_document(Default::default()).id,
                        &to,
                        &wallet.keypair(),
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(error) => serde_json::to_value(error.to_string()).unwrap(),
                    };
                    return Ok(Json(response));
                }
                false => {
                    let mut locked_connections = connections.try_lock().unwrap();
                    locked_connections.insert_message_for(*message, to).await;
                }
            },
            HandlerResponse::Response(product) => return Ok(Json(product)),
        }
    }
    Ok(Json(serde_json::json!({})))
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
async fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let mut config: Config = figment.extract().expect("loading config");
    let key = match config.key_seed.clone() {
        Some(seed) => generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap())),
        None => {
            let key = generate::<X25519KeyPair>(None);
            let seed = key.private_key_bytes().to_base58();
            println!("Generated Seed: {}", seed);
            config.key_seed = Some(seed);
            key
        }
    };
    config.did_key = Some(key.get_did_document(Default::default()).id);
    let wallet = Wallet::new_from_config(&config).await.unwrap();
    wallet.log();

    let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
        Arc::new(Mutex::new(Box::new(Connections::new())));

    rocket
        .attach(CORS)
        .mount(
            "/",
            routes![
                index,
                invitation_endpoint,
                didcomm_options,
                root_didcomm_endpoint,
                didcomm_endpoint,
                oob_invitation_endpoint,
                did_web_endpoint
            ],
        )
        .manage(config)
        .manage(wallet)
        .manage(connections)
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use did_key::{Ed25519KeyPair, CONFIG_JOSE_PUBLIC};
    use didcomm_mediator::message::add_return_route_all_header;
    use didcomm_mediator::message::sign_and_encrypt;
    use didcomm_mediator::protocols::didexchange::DidExchangeResponseBuilder;
    use didcomm_mediator::protocols::messagepickup::MessagePickupResponseBuilder;
    use didcomm_mediator::protocols::trustping::TrustPingResponseBuilder;
    use didcomm_rs::crypto::{CryptoAlgorithm, SignatureAlgorithm};
    use didcomm_rs::Message;
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::Client;

    #[tokio::test]
    async fn test_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        assert_eq!(services[0].typ, "did-communication");
    }

    #[tokio::test]
    async fn test_oob_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.post("/outofband/create-invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        assert_eq!(services[0].typ, "did-communication");
    }

    #[tokio::test]
    async fn test_didcomm_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let recipient_did = services[0].id.replace("#didcomm", "");
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
        assert_eq!(response.await.status(), Status::Ok);
    }

    #[tokio::test]
    async fn test_didcomm_wrong_key() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let recipient_did = services[0].id.replace("#didcomm", "");
        let recipient_key = did_key::resolve(&recipient_did).unwrap();
        let wrong_recipient_key = generate::<X25519KeyPair>(None);

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
                Some(vec![Some(wrong_recipient_key.public_key_bytes())]),
                SignatureAlgorithm::EdDsa,
                &[sign_key.private_key_bytes(), sign_key.public_key_bytes()].concat(),
            )
            .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(ready_to_send);
        let response = req.dispatch();
        assert_eq!(response.await.status(), Status::BadRequest);
    }

    #[tokio::test]
    async fn test_trust_ping() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let recipient_did = services[0].id.replace("#didcomm", "");
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
        assert_eq!(response.await.status(), Status::Ok);

        let request = MessagePickupResponseBuilder::new()
            .did(did_from.to_string())
            .batch_size(10)
            .build_batch_pickup()
            .unwrap();
        let request = sign_and_encrypt(
            &request,
            &key.get_did_document(Default::default()).id,
            &recipient_did,
            &key,
        )
        .await
        .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(serde_json::to_string(&request).unwrap());
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let response_json = response.into_string().await.unwrap();
        let received = Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);

        assert!(&received.is_ok());
        let message: Message = received.unwrap();

        println!("{:?}", message);

        for attachment in message.get_attachments() {
            let response_json = attachment.data.json.as_ref().unwrap();
            let received =
                Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);
            println!("message {:?}", received);
        }
        assert!(message.get_attachments().next().is_some());
    }

    #[tokio::test]
    async fn test_return_route() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let recipient_did = services[0].id.replace("#didcomm", "");
        let recipient_key = did_key::resolve(&recipient_did).unwrap();

        let key = generate::<X25519KeyPair>(None);
        let sign_key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let did_from = did_doc.id;

        let mut message = TrustPingResponseBuilder::new().build().unwrap();

        message = add_return_route_all_header(message);

        message = message
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
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let response_json = response.into_string().await.unwrap();
        let received = Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);

        assert!(&received.is_ok());
        let message: Message = received.unwrap();

        assert_eq!(
            message.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping-response"
        );
    }

    #[tokio::test]
    async fn test_did_exchange() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let recipient_did = services[0].id.replace("#didcomm", "");

        let key = generate::<X25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let did_from = did_doc.id.to_string();

        let invitation = Message::new()
            .m_type("https://didcomm.org/out-of-band/2.0/invitation")
            .thid(&invitation.get_didcomm_header().id)
            .from(&recipient_did);
        let request = DidExchangeResponseBuilder::new()
            .message(invitation.clone())
            .did(recipient_did.to_string())
            .did_doc(serde_json::to_value(&did_doc).unwrap())
            .build()
            .unwrap()
            .from(&did_from);

        let request = sign_and_encrypt(
            &request,
            &key.get_did_document(Default::default()).id,
            &recipient_did,
            &key,
        )
        .await
        .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(serde_json::to_string(&request).unwrap());
        let response = req.dispatch();
        assert_eq!(response.await.status(), Status::Ok);

        let request = MessagePickupResponseBuilder::new()
            .did(did_from.to_string())
            .batch_size(10)
            .build_batch_pickup()
            .unwrap();
        let request = sign_and_encrypt(
            &request,
            &key.get_did_document(Default::default()).id,
            &recipient_did,
            &key,
        )
        .await
        .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(serde_json::to_string(&request).unwrap());
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let response_json = response.into_string().await.unwrap();
        let received = Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);

        assert!(&received.is_ok());
        let message: Message = received.unwrap();

        for attachment in message.get_attachments() {
            let response_json = attachment.data.json.as_ref().unwrap();
            let received =
                Message::receive(&response_json, Some(&key.private_key_bytes()), None, None);
            println!("message {:?}", received);
        }
        assert!(message.get_attachments().next().is_some());
    }

    #[tokio::test]
    async fn test_forward() {
        let rocket = rocket();
        let client = Client::tracked(rocket.await).await.unwrap();
        let req = client.get("/invitation");
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let invitation: Message = response.into_json().await.unwrap();
        let (_, services) = invitation
            .get_application_params()
            .find(|(key, _)| *key == "services")
            .unwrap();
        let services: Vec<Service> = serde_json::from_str(services).unwrap();
        let mediator_did = services[0].id.replace("#didcomm", "");

        let alice_key = generate::<X25519KeyPair>(None);
        let did_doc = alice_key.get_did_document(CONFIG_JOSE_PUBLIC);
        let alice_did = did_doc.id.to_string();

        let bob_key = generate::<X25519KeyPair>(None);
        let did_doc = bob_key.get_did_document(CONFIG_JOSE_PUBLIC);
        let bob_did = did_doc.id.to_string();
        println!("bob did {}", bob_did);

        let ping_request = TrustPingResponseBuilder::new().build().unwrap();

        let ping_request = sign_and_encrypt(
            &ping_request,
            &alice_key.get_did_document(Default::default()).id,
            &bob_did,
            &alice_key,
        )
        .await
        .unwrap();

        let request = ForwardBuilder::new()
            .message(serde_json::to_string(&ping_request).unwrap())
            .did(bob_did.to_string())
            .build()
            .unwrap();
        let request = sign_and_encrypt(
            &request,
            &alice_key.get_did_document(Default::default()).id,
            &mediator_did,
            &alice_key,
        )
        .await
        .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(serde_json::to_string(&request).unwrap());
        let response = req.dispatch();
        assert_eq!(response.await.status(), Status::Ok);

        let request = MessagePickupResponseBuilder::new()
            .did(bob_did.to_string())
            .batch_size(10)
            .build_batch_pickup()
            .unwrap();
        let did_from = bob_key.get_did_document(Default::default()).id;
        let request = sign_and_encrypt(&request, &did_from, &mediator_did, &bob_key)
            .await
            .unwrap();

        let mut req = client.post("/didcomm");
        req.add_header(ContentType::JSON);
        let req = req.body(serde_json::to_string(&request).unwrap());
        let response = req.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        let response_json = response.into_string().await.unwrap();
        let received = Message::receive(
            &response_json,
            Some(&bob_key.private_key_bytes()),
            None,
            None,
        );

        assert!(&received.is_ok());
        let message: Message = received.unwrap();
        println!("message {}", message.clone().as_raw_json().unwrap());

        assert!(message.get_attachments().next().is_some());
        let pickup = message.get_attachments().next().unwrap();
        let response_json = pickup.data.json.as_ref().unwrap();
        let forwarded = Message::receive(
            &response_json,
            Some(&bob_key.private_key_bytes()),
            None,
            None,
        )
        .unwrap();
        assert!(forwarded.get_attachments().next().is_some());

        for attachment in forwarded.get_attachments() {
            let response_json = attachment.data.json.as_ref().unwrap();
            let received = Message::receive(
                &response_json,
                Some(&bob_key.private_key_bytes()),
                None,
                None,
            );
            assert_eq!(
                received.as_ref().unwrap().get_didcomm_header().m_type,
                "https://didcomm.org/trust-ping/2.0/ping"
            );
            assert_eq!(
                received
                    .as_ref()
                    .unwrap()
                    .get_didcomm_header()
                    .from
                    .as_ref()
                    .unwrap(),
                &alice_did
            );
            println!("message {:?}", received);
        }
    }
}
