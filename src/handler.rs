use crate::connections::ConnectionStorage;
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::Value;
use std::error::Error;
use std::sync::{Arc, Mutex};

#[derive(Debug, PartialEq)]
pub enum HandlerResponse {
    Skipped,
    Processed,
    Send(Box<Message>),
    Forward(Vec<String>, Value),
    Response(Value),
}

pub trait DidcommHandler {
    fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>>;
}
