use async_trait::async_trait;
use didcomm_rs::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum ConnectionEndpoint {
    Internal,
    Http(String),
}

impl Default for ConnectionEndpoint {
    fn default() -> Self {
        ConnectionEndpoint::Internal
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Clone)]
pub struct Connection {
    pub did: String,
    pub endpoint: ConnectionEndpoint,
    pub messages: VecDeque<Message>,
}

impl Connection {
    pub fn new(did: String, endpoint: ConnectionEndpoint) -> Self {
        Connection {
            did,
            endpoint,
            messages: VecDeque::default(),
        }
    }
}

#[async_trait]
pub trait ConnectionStorage: Send + Sync {
    async fn insert_message(&mut self, message: Message);
    async fn insert_message_for(&mut self, message: Message, did_to: String);
    async fn get_next(&mut self, did: String) -> Option<Message>;
    async fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>>;
    async fn get(&self, did: String) -> Option<Connection>;
}

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Connections {
    pub connections: HashMap<String, Connection>,
}

impl Connections {
    pub fn new() -> Connections {
        Connections::default()
    }
}

unsafe impl Send for Connections {}
unsafe impl Sync for Connections {}

#[async_trait]
impl ConnectionStorage for Connections {
    async fn insert_message(&mut self, message: Message) {
        let dids = message.get_didcomm_header().to.to_vec();
        for did in &dids {
            match self.connections.get_mut(did) {
                Some(connection) => {
                    connection.messages.push_back(message.clone());
                }
                None => {
                    let mut connection = Connection::new(did.to_string(), Default::default());
                    connection.messages.push_back(message.clone());
                    self.connections.insert(did.to_string(), connection);
                }
            }
        }
    }

    async fn insert_message_for(&mut self, message: Message, did_to: String) {
        match self.connections.get_mut(&did_to) {
            Some(connection) => {
                connection.messages.push_back(message);
            }
            None => {
                let mut connection = Connection::new(did_to.to_string(), Default::default());
                connection.messages.push_back(message);
                self.connections.insert(did_to.to_string(), connection);
            }
        }
    }

    async fn get_next(&mut self, did: String) -> Option<Message> {
        match self.connections.get_mut(&did) {
            Some(connection) => connection.messages.pop_front(),
            None => None,
        }
    }

    async fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>> {
        match self.connections.get_mut(&did) {
            Some(connection) => {
                let messages = connection
                    .messages
                    .drain(0..batch_size.min(connection.messages.len()));

                let messages: Vec<Message> = messages.collect();
                Some(messages)
            }
            None => None,
        }
    }

    async fn get(&self, did: String) -> Option<Connection> {
        self.connections.get(&did).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_message() {
        let mut connections = Connections::default();
        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message).await;

        assert_eq!(connections.connections.len(), 1);

        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message).await;

        assert_eq!(connections.connections.len(), 1);
        let connection = connections.connections.get("did:test").unwrap();
        assert_eq!(connection.messages.len(), 2);
    }
}
