use didcomm_mediator::connections::{Connection, ConnectionStorage};
use didcomm_rs::Message;
use serde::Deserialize;
use worker_kv::KvStore;

fn kv() -> KvStore {
    KvStore::create("didcomm-mediator-worker").unwrap()
}

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Connections {}

impl Connections {
    pub fn new() -> Connections {
        Default::default()
    }
}

impl ConnectionStorage for Connections {
    fn insert_message(&mut self, message: Message) {
        let dids = message.get_didcomm_header().to.to_vec();
        for did in &dids {
            self.insert_message_for(message.clone(), did.to_string());
        }
    }

    fn insert_message_for(&mut self, message: Message, did_to: String) {
        let mut connection = match self.get(did_to.to_string()) {
            Some(connection) => connection.clone(),
            None => Connection::new(did_to.to_string(), Default::default()),
        };
        connection.messages.push_back(message.clone());
        futures::executor::block_on(async {
            kv().put(&did_to, connection).unwrap().execute().await
        })
        .unwrap();
    }

    fn get_next(&mut self, did: String) -> Option<Message> {
        match self.get(did.to_string()) {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let message = connection.messages.pop_front();
                futures::executor::block_on(async {
                    kv().put(&did, connection).unwrap().execute().await
                })
                .unwrap();
                message
            }
            None => None,
        }
    }

    fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>> {
        match self.get(did.to_string()) {
            Some(connection) => {
                let mut connection: Connection = connection.clone();
                let messages = connection
                    .messages
                    .drain(0..batch_size.min(connection.messages.len()));

                let messages: Vec<Message> = messages.collect();
                futures::executor::block_on(async {
                    kv().put(&did, connection).unwrap().execute().await
                })
                .unwrap();

                Some(messages)
            }
            None => None,
        }
    }

    fn get(&self, did: String) -> Option<Connection> {
        futures::executor::block_on(async { kv().get(&did).json().await }).unwrap()
    }
}
