use didcomm_rs::Message;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Deserialize)]
pub enum ConnectionEndpoint {
    Internal,
    Http(String),
}

impl Default for ConnectionEndpoint {
    fn default() -> Self {
        ConnectionEndpoint::Internal
    }
}

#[derive(Debug, Default, PartialEq, Deserialize)]
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

pub trait ConnectionStorage: Send {
    fn insert_message(&mut self, message: Message);
    fn insert_message_for(&mut self, message: Message, did_to: String);
    fn get_next(&mut self, did: String) -> Option<Message>;
    fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>>;
    fn get(&self, did: String) -> Option<&Connection>;
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

impl ConnectionStorage for Connections {
    fn insert_message(&mut self, message: Message) {
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

    fn insert_message_for(&mut self, message: Message, did_to: String) {
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

    fn get_next(&mut self, did: String) -> Option<Message> {
        match self.connections.get_mut(&did) {
            Some(connection) => connection.messages.pop_front(),
            None => None,
        }
    }

    fn get_messages(&mut self, did: String, batch_size: usize) -> Option<Vec<Message>> {
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

    fn get(&self, did: String) -> Option<&Connection> {
        self.connections.get(&did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_message() {
        let mut connections = Connections::default();
        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message);

        assert_eq!(connections.connections.len(), 1);

        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message);

        assert_eq!(connections.connections.len(), 1);
        let connection = connections.connections.get("did:test").unwrap();
        assert_eq!(connection.messages.len(), 2);
    }
}
