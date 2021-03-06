use crate::connections::ConnectionStorage;
use async_mutex::Mutex;
use async_trait::async_trait;
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::Value;
use std::error::Error;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub enum HandlerResponse {
    Skipped,
    Processed,
    Send(String, Box<Message>),
    Forward(Vec<String>, Value),
    Response(Value),
}

unsafe impl Send for HandlerResponse {}
unsafe impl Sync for HandlerResponse {}

#[async_trait]
pub trait DidcommHandler: Send + Sync {
    async fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>>;
}
