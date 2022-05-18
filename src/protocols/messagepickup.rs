// https://github.com/hyperledger/aries-rfcs/tree/main/features/0212-pickup
use crate::connections::Connections;
use crate::handler::{DidcommHandler, HandlerResponse};
use crate::message::sign_and_encrypt_message;
use chrono::{DateTime, Utc};
use did_key::KeyPair;
use did_key::{DIDCore, CONFIG_LD_PUBLIC};
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
pub struct MessagePickupResponseBuilder<'a> {
    did: Option<String>,
    message: Option<Message>,
    connections: Option<&'a Arc<Mutex<Connections>>>,
    batch_size: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MessagePickupStatus {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub m_type: String,
    pub message_count: u32,
    pub duration_waited: u32,
    pub last_added_time: DateTime<Utc>,
    pub last_delivered_time: DateTime<Utc>,
    pub last_removed_time: DateTime<Utc>,
    pub total_size: u32,
}

impl Default for MessagePickupStatus {
    fn default() -> Self {
        MessagePickupStatus {
            id: Uuid::new_v4().to_string(),
            m_type: "https://didcomm.org/messagepickup/1.0/status".to_string(),
            message_count: 0,
            duration_waited: 0,
            last_added_time: Utc::now(),
            last_delivered_time: Utc::now(),
            last_removed_time: Utc::now(),
            total_size: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MessageBatch {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub m_type: String,
    #[serde(rename = "messages~attach")]
    pub messages_attach: Vec<Value>,
}

impl Default for MessageBatch {
    fn default() -> Self {
        MessageBatch {
            id: Uuid::new_v4().to_string(),
            m_type: "https://didcomm.org/messagepickup/1.0/batch".to_string(),
            messages_attach: Vec::new(),
        }
    }
}

impl<'a> MessagePickupResponseBuilder<'a> {
    pub fn new() -> Self {
        MessagePickupResponseBuilder {
            did: None,
            message: None,
            connections: None,
            batch_size: None,
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn batch_size(&mut self, batch_size: u32) -> &mut Self {
        self.batch_size = Some(batch_size);
        self
    }

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn connections(&mut self, connections: &'a Arc<Mutex<Connections>>) -> &mut Self {
        self.connections = Some(connections);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "https://didcomm.org/messagepickup/1.0/status-request" => self.build_status(),
                "https://didcomm.org/messagepickup/1.0/batch-pickup" => self.build_batch(),
                _ => Err("unsupported message"),
            },
            None => self.build_status_request(),
        }
    }

    pub fn build_status_request(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new().m_type("https://didcomm.org/messagepickup/1.0/status-request"))
    }

    fn build_status(&mut self) -> Result<Message, &'static str> {
        let status: MessagePickupStatus = match &self.connections {
            Some(connections) => {
                let connections = connections.try_lock().unwrap();
                let connection = connections.connections.get(self.did.as_ref().unwrap());
                match connection {
                    Some(connection) => MessagePickupStatus {
                        message_count: connection.messages.len() as u32,
                        ..Default::default()
                    },
                    _ => MessagePickupStatus::default(),
                }
            }
            None => MessagePickupStatus::default(),
        };

        Ok(Message::new()
            .m_type("https://didcomm.org/messagepickup/1.0/status")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .body(&serde_json::to_string(&status).unwrap()))
    }

    pub fn build_batch_pickup(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/messagepickup/1.0/batch-pickup")
            .add_header_field(
                "batch_size".to_string(),
                format!("{}", self.batch_size.unwrap()),
            ))
    }

    fn build_batch(&mut self) -> Result<Message, &'static str> {
        let batch: Message = match &self.connections {
            Some(connections) => {
                let connections = connections.try_lock().unwrap();
                let did_from: String = self
                    .message
                    .as_ref()
                    .unwrap()
                    .get_didcomm_header()
                    .from
                    .clone()
                    .unwrap();
                let connection = connections.connections.get(&did_from);
                match connection {
                    Some(connection) => {
                        let (_, batch_size) = self
                            .message
                            .as_ref()
                            .unwrap()
                            .get_application_params()
                            .filter(|(key, _)| *key == "batch_size")
                            .next()
                            .unwrap();
                        let batch_size = batch_size.clone().parse::<u64>().unwrap();
                        let messages: Vec<Message> =
                            connection.messages.clone().into_iter().collect();
                        let messages =
                            messages[0..batch_size.min(messages.len() as u64) as usize].to_vec();
                        let attachments: Vec<AttachmentBuilder> =
                            messages
                                .into_iter()
                                .map(|message| {
                                    AttachmentBuilder::new(true)
                                        .with_id(&Uuid::new_v4().to_string())
                                        .with_data(AttachmentDataBuilder::new().with_raw_payload(
                                            serde_json::to_string(&message).unwrap(),
                                        ))
                                })
                                .collect();
                        let mut message = Message::new();
                        for attachment in attachments {
                            message.append_attachment(attachment);
                        }
                        message
                    }
                    _ => Message::new(),
                }
            }
            None => Message::new(),
        };

        Ok(batch
            .m_type("https://didcomm.org/messagepickup/1.0/batch")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }
}

#[derive(Default)]
pub struct MessagePickupHandler {}

impl DidcommHandler for MessagePickupHandler {
    fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        connections: Option<&Arc<Mutex<Connections>>>,
    ) -> HandlerResponse {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/messagepickup/1.0/")
        {
            let did = key.unwrap().get_did_document(CONFIG_LD_PUBLIC).id;
            let response = MessagePickupResponseBuilder::new()
                .message(request.clone())
                .did(did)
                .connections(connections.unwrap())
                .build()
                .unwrap();
            let response = sign_and_encrypt_message(request, &response, key.unwrap());

            HandlerResponse::Response(serde_json::to_value(&response).unwrap())
        } else {
            HandlerResponse::Skipped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_key::{generate, X25519KeyPair};

    #[test]
    fn test_build_status_request() {
        let response = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .unwrap();
        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_status() {
        let mut request = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .unwrap();
        request = request.from("did:test");

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );

        let mut connections = Connections::default();
        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message);

        let response = MessagePickupResponseBuilder::new()
            .connections(&Arc::new(Mutex::new(connections)))
            .message(request)
            .did("did:test".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status"
        );
        let response_body = response.get_body().unwrap();
        assert_ne!(response_body, "{}");
        let status: MessagePickupStatus = serde_json::from_str(&response_body).unwrap();
        assert_eq!(status.message_count, 1);

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_batch_size() {
        let response = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .batch_size(10)
            .build_batch_pickup()
            .unwrap();
        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/batch-pickup"
        );
        let (_, batch_size) = response
            .get_application_params()
            .filter(|(key, _)| *key == "batch_size")
            .next()
            .unwrap();
        assert_eq!(batch_size, "10");
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_batch() {
        let mut request = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .batch_size(1)
            .build_batch_pickup()
            .unwrap();
        request = request.from("did:test");

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/batch-pickup"
        );

        let mut connections = Connections::default();
        let message1 = Message::new().to(&["did:test"]);
        connections.insert_message(message1);
        let message2 = Message::new().to(&["did:test"]);
        connections.insert_message(message2);

        let response = MessagePickupResponseBuilder::new()
            .connections(&Arc::new(Mutex::new(connections)))
            .message(request)
            .did("did:test".to_string())
            .build_batch()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/batch"
        );

        assert!(response.get_attachments().next().is_some());

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let request = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .unwrap();
        let request = request.from(&key.get_did_document(Default::default()).id);

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );
        let handler = MessagePickupHandler::default();
        let response = handler.handle(
            &request,
            Some(&key),
            Some(&Arc::new(Mutex::new(Default::default()))),
        );
        assert_ne!(response, HandlerResponse::Skipped);
    }
}
