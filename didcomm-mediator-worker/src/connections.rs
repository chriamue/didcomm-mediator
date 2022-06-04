use async_trait::async_trait;
use didcomm_mediator::connections::{Connection, ConnectionStorage};
use didcomm_rs::Message;
use kv::KvError;
use serde::Deserialize;
use worker::*;
use worker_kv::KvStore;

pub fn kv() -> std::result::Result<KvStore, KvError> {
    match KvStore::create("KV_CONNECTIONS") {
        Ok(kv) => Ok(kv),
        Err(error) => {
            console_log!("{:?}", error.to_string());
            Err(error)
        }
    }
}

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
            self.insert_message_for(message.clone(), did.to_string()).await;
        }
    }

    async fn insert_message_for(&mut self, message: Message, did_to: String) {
        let mut connection = match self.get(did_to.to_string()).await {
            Some(connection) => connection.clone(),
            None => Connection::new(did_to.to_string(), Default::default()),
        };
        connection.messages.push_back(message.clone());
        match futures::executor::block_on(async {
            kv().unwrap()
                .put(&did_to, connection)
                .unwrap()
                .execute()
                .await
        }) {
            Ok(_) => (),
            Err(error) => console_log!("{:?}", error),
        };
    }

    async fn get_next(&mut self, did: String) -> Option<Message> {
        match self.get(did.to_string()).await {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let message = connection.messages.pop_front();
                match futures::executor::block_on(async {
                    kv().unwrap().put(&did, connection).unwrap().execute().await
                }) {
                    Ok(_) => (),
                    Err(error) => console_log!("{:?}", error),
                };
                message
            }
            None => None,
        }
    }

    async fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>> {
        match self.get(did.to_string()).await {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let messages = connection
                    .messages
                    .drain(0..batch_size.min(connection.messages.len()));

                let messages: Vec<Message> = messages.collect();
                match futures::executor::block_on(async {
                    kv().unwrap().put(&did, connection).unwrap().execute().await
                }) {
                    Ok(_) => (),
                    Err(error) => console_log!("{:?}", error),
                };
                Some(messages)
            }
            None => None,
        }
    }

    async fn get(&self, did: String) -> Option<Connection> {
        match futures::executor::block_on(async { kv().unwrap().get(&did).json().await }) {
            Ok(connection) => connection,
            Err(error) => {
                console_log!("{:?}", error);
                None
            }
        }
    }
}
