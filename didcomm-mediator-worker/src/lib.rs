use base58::FromBase58;
use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair, CONFIG_LD_PUBLIC};
use didcomm_mediator::connections::ConnectionStorage;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use worker::*;
pub mod connections;
pub mod utils;
use async_mutex::Mutex;
use didcomm_mediator::handler::{DidcommHandler, HandlerResponse};
use didcomm_mediator::message::{has_return_route_all_header, sign_and_encrypt};
use didcomm_mediator::protocols::didexchange::DidExchangeHandler;
use didcomm_mediator::protocols::didexchange::DidExchangeResponseBuilder;
use didcomm_mediator::protocols::discoverfeatures::DiscoverFeaturesHandler;
use didcomm_mediator::protocols::forward::ForwardBuilder;
use didcomm_mediator::protocols::forward::ForwardHandler;
use didcomm_mediator::protocols::invitation::InvitationBuilder;
use didcomm_mediator::protocols::messagepickup::MessagePickupHandler;
use didcomm_mediator::protocols::trustping::TrustPingHandler;
use didcomm_mediator::service::Service;
use didcomm_rs::Message;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

#[wasm_bindgen]
extern "C" {
    type KV;

    #[wasm_bindgen(static_method_of = KV)]
    pub async fn get(s: String) -> JsValue;

    #[wasm_bindgen(static_method_of = KV)]
    pub async fn put(key: String, value: JsValue);
}

// source: https://github.com/rodneylab/hcaptcha-serverless-rust-worker/blob/main/src/lib.rs
fn preflight_response(_headers: &worker::Headers, _cors_origin: &str) -> Result<Response> {
    let mut headers = worker::Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "*")?;
    headers.set("Access-Control-Allow-Credentials", "true")?;
    headers.set("Access-Control-Max-Age", "600")?;
    Ok(Response::empty()
        .unwrap()
        .with_headers(headers)
        .with_status(204))
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new();
    router
        .get("/", |_, _| Response::ok("Mediator"))
        .options("/didcomm", |req, _ctx| {
            preflight_response(req.headers(), "")
        })
        .options("/invitation", |req, _ctx| {
            preflight_response(req.headers(), "")
        })
        .get_async("/invitation", |_req, ctx| async move {
            let seed = ctx.secret("SEED").unwrap().to_string();
            let _ident = ctx.var("IDENT").unwrap().to_string();
            let ext_service = ctx.var("EXT_SERVICE").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));

            let mut did_doc = key.get_did_document(CONFIG_LD_PUBLIC);
            did_doc.verification_method[0].private_key = None;

            let did_exchange = DidExchangeResponseBuilder::new()
                .did_doc(serde_json::to_value(&did_doc).unwrap())
                .did(did_doc.id.to_string())
                .build_request()
                .unwrap();

            let services: Vec<Service> = vec![Service::new(did_doc.id, ext_service).await.unwrap()];
            let invitation = InvitationBuilder::new()
                .goal("to create a relationship".to_string())
                .goal_code("aries.rel.build".to_string())
                .services(services)
                .attachments(vec![did_exchange])
                .build()
                .unwrap();

            let mut headers = worker::Headers::new();
            headers.set("Access-Control-Allow-Methods", "GET")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Access-Control-Allow-Headers", "*")?;
            headers.set("Access-Control-Allow-Credentials", "true")?;
            let response = Response::from_json(&json!(invitation)).unwrap();
            Ok(response.with_headers(headers))
        })
        .get("/.well-known/did.json", |_req, ctx| {
            let seed = ctx.secret("SEED").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
            let ext_service = ctx.var("EXT_SERVICE").unwrap().to_string();
            let mut did_doc = key.get_did_document(CONFIG_LD_PUBLIC);
            did_doc.verification_method[0].private_key = None;
            let mut did_doc = serde_json::to_value(&did_doc).unwrap();
            did_doc["service"] = serde_json::json!([
              {
                "id": "2e9e814a-c1e1-416e-a21a-a4182809950c",
                "serviceEndpoint": ext_service,
                "type": "did-communication"
              }
            ]);
            Response::from_json(&did_doc)
        })
        .post_async("/didcomm", |mut req, ctx| async move {
            let body: Value = match req.json().await {
                Ok(res) => res,
                Err(_) => return Response::error("Bad request", 400),
            };
            let body_str = serde_json::to_string(&body).unwrap();
            let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
                Arc::new(Mutex::new(Box::new(connections::Connections::new())));
            let seed = ctx.secret("SEED").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
            let mut headers = worker::Headers::new();
            headers.set("Access-Control-Allow-Methods", "POST")?;
            headers.set("Content-Type", "application/json")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Access-Control-Allow-Headers", "*")?;
            headers.set("Access-Control-Allow-Credentials", "true")?;

            let received =
                match Message::receive(&body_str, Some(&key.private_key_bytes()), None, None) {
                    Ok(received) => received,
                    Err(error) => return Response::error(format!("{:?}", error), 400),
                };

            let handlers: Vec<Box<dyn DidcommHandler>> = vec![
                Box::new(ForwardHandler::default()),
                Box::new(DidExchangeHandler::default()),
                Box::new(DiscoverFeaturesHandler::default()),
                Box::new(TrustPingHandler::default()),
                Box::new(MessagePickupHandler::default()),
            ];

            for handler in handlers {
                match handler
                    .handle(&received, Some(&key), Some(&connections))
                    .await
                {
                    Ok(HandlerResponse::Skipped) => {}
                    Ok(HandlerResponse::Processed) => {}
                    Ok(HandlerResponse::Forward(receivers, message)) => {
                        for receiver in receivers {
                            let forward = ForwardBuilder::new()
                                .did(receiver.to_string())
                                .message(serde_json::to_string(&message).unwrap())
                                .build()
                                .unwrap();
                            let mut locked_connections = connections.try_lock().unwrap();
                            locked_connections
                                .insert_message_for(forward.clone(), receiver.to_string())
                                .await;
                        }
                    }
                    Ok(HandlerResponse::Send(to, message)) => {
                        match has_return_route_all_header(&received) {
                            true => {
                                let response = match sign_and_encrypt(
                                    &message,
                                    &key.get_did_document(Default::default()).id,
                                    &to,
                                    &key,
                                )
                                .await
                                {
                                    Ok(response) => response,
                                    Err(error) => serde_json::to_value(error.to_string()).unwrap(),
                                };
                                let response = Response::from_json(&json!(response)).unwrap();
                                return Ok(response.with_headers(headers));
                            }
                            false => {
                                let mut locked_connections = connections.try_lock().unwrap();
                                locked_connections.insert_message_for(*message, to).await;
                            }
                        }
                    }
                    Ok(HandlerResponse::Response(product)) => {
                        let response = Response::from_json(&product).unwrap();
                        return Ok(response.with_headers(headers));
                    }
                    Err(error) => return Response::error(format!("{:?}", error), 400),
                }
            }
            let response = Response::from_json(&json!({})).unwrap();
            Ok(response.with_headers(headers))
        })
        .run(req, env)
        .await
}
