use crate::connections::Connections;
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum HandlerResponse {
    Skipped,
    Processed,
    Produced(Value),
}

pub trait Handler {
    fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        connections: Option<&Connections>,
    ) -> HandlerResponse;
}
