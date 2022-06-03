use base58::FromBase58;
use did_key::{generate, DIDCore, X25519KeyPair, CONFIG_JOSE_PUBLIC};
use didcomm_mediator::invitation::Invitation;
use serde_json::json;
use worker::*;

mod utils;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new();
    router
        .get("/", |_, _| Response::ok("Hello from Workers!"))
        .get("/invitation", |_req, ctx| {
            let seed = ctx.secret("SEED").unwrap().to_string();
            let ident = ctx.var("IDENT").unwrap().to_string();
            let ext_service = ctx.var("EXT_SERVICE").unwrap().to_string();
            let key = generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
            let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
            let did = did_doc.id;
            Response::from_json(&json!({
                "invitation": Invitation::new(
                    did,
                    ident,
                    ext_service
                ),
            }))
        })
        .run(req, env)
        .await
}
