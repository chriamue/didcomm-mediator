use crate::KV;
use async_trait::async_trait;
use didcomm_mediator::connections::{Connection, ConnectionStorage};
use didcomm_rs::Message;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use worker::*;

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Connections {}

impl Connections {
    pub fn new() -> Connections {
        Default::default()
    }
}

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
        let mut connection = match self.get(did_to.to_string()).await {
            Some(connection) => connection.clone(),
            None => Connection::new(did_to.to_string(), Default::default()),
        };
        connection.messages.push_back(message.clone());
        let value = JsValue::from_serde(&connection).unwrap();
        futures::executor::block_on(async {
            KV::put(did_to, value.clone()).await;
        });
    }

    async fn get_next(&mut self, did: String) -> Option<Message> {
        let message = match self.get(did.to_string()).await {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let message = connection.messages.pop_front();
                let value = JsValue::from_serde(&connection).unwrap();
                futures::executor::block_on(async {
                    KV::put(did, value.clone()).await;
                });
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
                let value = JsValue::from_serde(&connection).unwrap();
                futures::executor::block_on(async {
                    KV::put(did, value.clone()).await;
                });
                Some(messages)
            }
            None => None,
        }
    }

    async fn get(&self, did: String) -> Option<Connection> {
        let value = futures::executor::block_on(async { KV::get(did).await });
        let connection: Option<Connection> = JsValue::into_serde(&value).unwrap();
        connection
        /*
        match futures::executor::block_on(async { kv().unwrap().get(&did).json().await }) {
            Ok(connection) => connection,
            Err(error) => {
                console_log!("{:?}", error);
                None
            }
        }
        */
    }
}
