// https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20
use crate::connections::Connections;
use didcomm_rs::Message;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct PollResponseBuilder {
    did: Option<String>,
    message: Option<Message>,
    connections: Option<Arc<Mutex<Connections>>>,
}

impl PollResponseBuilder {
    pub fn new() -> Self {
        PollResponseBuilder {
            did: None,
            message: None,
            connections: None,
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn connections(&mut self, connections: Arc<Mutex<Connections>>) -> &mut Self {
        self.connections = Some(connections);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "poll/0.1/request" => self.build_response(),
                _ => Err("unsupported message"),
            },
            None => self.build_request(),
        }
    }

    fn build_request(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("poll/0.1/request")
            .body(&json!({"response_requested": true}).to_string()))
    }

    fn build_response(&mut self) -> Result<Message, &'static str> {
        let message = match &self.connections {
            Some(connections) => {
                let mut connections = connections.try_lock().unwrap();
                connections.get_next(self.did.as_ref().unwrap().to_string())
            }
            None => None,
        };
        let message_json: String = match message {
            Some(message) => message.as_raw_json().unwrap(),
            None => "{}".to_string(),
        };
        Ok(Message::new()
            .m_type("poll/0.1/response")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .body(&message_json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request() {
        let response = PollResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .unwrap();

        assert_eq!(response.get_didcomm_header().m_type, "poll/0.1/request");

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let mut poll = PollResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .unwrap();
        poll = poll.from("did:test");

        assert_eq!(poll.get_didcomm_header().m_type, "poll/0.1/request");

        let mut connections = Connections::default();
        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message);

        let response = PollResponseBuilder::new()
            .connections(Arc::new(Mutex::new(connections)))
            .message(poll)
            .did("did:test".to_string())
            .build()
            .unwrap();

        assert_eq!(response.get_didcomm_header().m_type, "poll/0.1/response");
        assert_ne!(response.get_body().unwrap(), "{}");

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
