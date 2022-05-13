use didcomm_rs::Message;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::VecDeque;

#[derive(Default, PartialEq, Deserialize)]
pub struct Connection {
    pub did: String,
    pub messages: VecDeque<Message>,
}

impl Connection {
    pub fn new(did: String) -> Self {
        Connection {
            did,
            messages: VecDeque::default(),
        }
    }
}

#[derive(Default, PartialEq, Deserialize)]
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
                    let mut connection = Connection::new(did.to_string());
                    connection.messages.push_back(message.clone());
                    self.connections.insert(did.to_string(), connection);
                }
            }
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
