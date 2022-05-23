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

#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Connections {
    pub connections: HashMap<String, Connection>,
}

impl Connections {
    pub fn new() -> Connections {
        Connections::default()
    }

    pub fn insert_message(&mut self, message: Message) {
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

    pub fn insert_message_for(&mut self, message: Message, did_to: String) {
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

    pub fn get_next(&mut self, did: String) -> Option<Message> {
        match self.connections.get_mut(&did) {
            Some(connection) => connection.messages.pop_front(),
            None => None,
        }
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
