use base58::FromBase58;
use did_key::{
    generate, DIDCore, KeyMaterial, X25519KeyPair, CONFIG_JOSE_PUBLIC, CONFIG_LD_PUBLIC,
};
use didcomm_mediator::connections::ConnectionStorage;
use didcomm_mediator::invitation::Invitation;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use worker::*;
mod connections;
mod utils;
use didcomm_rs::Message;

use didcomm_mediator::handler::{DidcommHandler, HandlerResponse};
use didcomm_mediator::protocols::didexchange::DidExchangeHandler;
use didcomm_mediator::protocols::discoverfeatures::DiscoverFeaturesHandler;
use didcomm_mediator::protocols::forward::ForwardBuilder;
use didcomm_mediator::protocols::forward::ForwardHandler;
use didcomm_mediator::protocols::messagepickup::MessagePickupHandler;
use didcomm_mediator::protocols::trustping::TrustPingHandler;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
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
        .get("/invitation", |_req, ctx| {
            let seed = ctx.secret("SEED").unwrap().to_string();
            let ident = ctx.var("IDENT").unwrap().to_string();
            let ext_service = ctx.var("EXT_SERVICE").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
            let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
            let did = did_doc.id;
            let mut headers = worker::Headers::new();
            headers.set("Access-Control-Allow-Methods", "GET")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Access-Control-Allow-Headers", "*")?;
            headers.set("Access-Control-Allow-Credentials", "true")?;
            let response = Response::from_json(&json!({
                "invitation": Invitation::new(
                    did,
                    ident,
                    ext_service
                ),
            }))
            .unwrap();
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
            let body: Value = req.json().await.unwrap();
            let body_str = serde_json::to_string(&body).unwrap();
            console_log!("{}", body_str);
            let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
                Arc::new(Mutex::new(Box::new(connections::Connections::new())));
            let seed = ctx.secret("SEED").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
            let mut headers = worker::Headers::new();
            headers.set("Access-Control-Allow-Methods", "POST")?;
            headers.set("Access-Control-Allow-Origin", "*")?;
            headers.set("Access-Control-Allow-Headers", "*")?;
            headers.set("Access-Control-Allow-Credentials", "true")?;

            let received =
                Message::receive(&body_str, Some(&key.private_key_bytes()), None, None).unwrap();

            let handlers: Vec<Box<dyn DidcommHandler>> = vec![
                Box::new(ForwardHandler::default()),
                Box::new(DidExchangeHandler::default()),
                Box::new(DiscoverFeaturesHandler::default()),
                Box::new(TrustPingHandler::default()),
                Box::new(MessagePickupHandler::default()),
            ];

            for handler in handlers {
                match handler.handle(&received, Some(&key), Some(&connections)) {
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
                            locked_connections.insert_message_for(forward, receiver.to_string());
                        }
                    }
                    HandlerResponse::Send(message) => {
                        let mut locked_connections = connections.try_lock().unwrap();
                        locked_connections.insert_message(*message);
                    }
                    HandlerResponse::Response(product) => {
                        let response = Response::from_json(&product).unwrap();
                        return Ok(response.with_headers(headers));
                    }
                }
            }

            let response = Response::from_json(&json!({})).unwrap();
            Ok(response.with_headers(headers))
        })
        .run(req, env)
        .await
}
