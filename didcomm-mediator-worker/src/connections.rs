use crate::KV;
use async_trait::async_trait;
use didcomm_mediator::connections::{Connection, ConnectionStorage};
use didcomm_rs::Message;
use serde::Deserialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use worker::*;

pub fn get(key: String) -> Value {
    let value = futures::executor::block_on(async { KV::get(key).await });
    JsValue::into_serde(&value).unwrap()
}

pub fn put(did: String, value: Value) {
    let value = JsValue::from_serde(&value).unwrap();
    futures::executor::block_on(async { KV::put(did.to_string(), value).await });
}

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Connections {}

impl Connections {
    pub fn new() -> Connections {
        Default::default()
    }
}

unsafe impl Send for Connections {}
unsafe impl Sync for Connections {}

#[async_trait]
impl ConnectionStorage for Connections {
    async fn insert_message(&mut self, message: Message) {
        let dids = message.get_didcomm_header().to.to_vec();
        for did in &dids {
            self.insert_message_for(message.clone(), did.to_string())
                .await;
        }
    }

    async fn insert_message_for(&mut self, message: Message, did_to: String) {
        console_log!("{}, {:?}", did_to, message);
        let mut connection = match self.get(did_to.to_string()).await {
            Some(connection) => connection.clone(),
            None => Connection::new(did_to.to_string(), Default::default()),
        };
        connection.messages.push_back(message.clone());
        let value = serde_json::to_value(&connection).unwrap();
        put(did_to, value);
    }

    async fn get_next(&mut self, did: String) -> Option<Message> {
        let message = match self.get(did.to_string()).await {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let message = connection.messages.pop_front();
                let value = serde_json::to_value(&connection).unwrap();
                put(did, value);
                message
            }
            None => None,
        };
        message
    }

    async fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>> {
        match self.get(did.to_string()).await {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let messages = connection
                    .messages
                    .drain(0..batch_size.min(connection.messages.len()));

                let messages: Vec<Message> = messages.collect();
                let value = serde_json::to_value(&connection).unwrap();
                put(did, value);
                Some(messages)
            }
            None => None,
        }
    }

    async fn get(&self, did: String) -> Option<Connection> {
        let did = did.to_string();
        let connection: Option<Connection> = serde_json::from_value(get(did)).unwrap();
        connection
    }
}
