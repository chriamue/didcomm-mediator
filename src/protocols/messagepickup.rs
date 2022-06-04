// https://github.com/hyperledger/aries-rfcs/tree/main/features/0212-pickup
use crate::connections::ConnectionStorage;
use crate::handler::{DidcommHandler, HandlerResponse};
use crate::message::sign_and_encrypt_message;
use async_mutex::Mutex;
use async_trait::async_trait;
use did_key::KeyPair;
use did_key::{DIDCore, CONFIG_LD_PUBLIC};
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use std::error::Error;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Default)]
pub struct MessagePickupResponseBuilder<'a> {
    did: Option<String>,
    message: Option<Message>,
    connections: Option<&'a Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    batch_size: Option<u32>,
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

    pub fn connections(
        &mut self,
        connections: &'a Arc<Mutex<Box<dyn ConnectionStorage>>>,
    ) -> &mut Self {
        self.connections = Some(connections);
        self
    }

    pub async fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "https://didcomm.org/messagepickup/1.0/status-request" => self.build_status().await,
                "https://didcomm.org/messagepickup/1.0/batch-pickup" => self.build_batch().await,
                _ => Err("unsupported message"),
            },
            None => self.build_status_request(),
        }
    }

    pub fn build_status_request(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new().m_type("https://didcomm.org/messagepickup/1.0/status-request"))
    }

    async fn build_status(&mut self) -> Result<Message, &'static str> {
        let message: Message = {
            let connection = {
                let muted = self.connections.unwrap().try_lock().unwrap();
                muted.get(self.did.as_ref().unwrap().to_string()).await
            };
            match connection {
                Some(connection) => Message::new().add_header_field(
                    "message_count".to_string(),
                    format!("{}", connection.messages.len()),
                ),
                _ => Message::new().add_header_field("message_count".to_string(), format!("{}", 0)),
            }
        };

        Ok(message
            .m_type("https://didcomm.org/messagepickup/1.0/status")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }

    pub fn build_batch_pickup(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/messagepickup/1.0/batch-pickup")
            .add_header_field(
                "batch_size".to_string(),
                format!("{}", self.batch_size.unwrap()),
            ))
    }

    async fn build_batch(&mut self) -> Result<Message, &'static str> {
        let did_from: String = self
            .message
            .as_ref()
            .unwrap()
            .get_didcomm_header()
            .from
            .clone()
            .unwrap();
        let (_, batch_size) = self
            .message
            .as_ref()
            .unwrap()
            .get_application_params()
            .find(|(key, _)| *key == "batch_size")
            .unwrap();
        let batch_size = batch_size.clone().parse::<usize>().unwrap();

        let messages = {
            let mut connections = self.connections.unwrap().try_lock().unwrap();
            let messages = connections.get_messages(did_from, batch_size).await;
            messages.clone()
        };

        let batch: Message = match messages {
            Some(messages) => {
                let attachments: Vec<AttachmentBuilder> = messages
                    .into_iter()
                    .map(|message| {
                        AttachmentBuilder::new(true)
                            .with_id(&Uuid::new_v4().to_string())
                            .with_data(
                                AttachmentDataBuilder::new()
                                    .with_link("no")
                                    .with_json(&serde_json::to_string(&message).unwrap()),
                            )
                    })
                    .collect();

                let mut message = Message::new();
                for attachment in attachments {
                    message.append_attachment(attachment);
                }

                message
            }
            _ => Message::new(),
        };

        Ok(batch
            .m_type("https://didcomm.org/messagepickup/1.0/batch")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }
}

#[derive(Default)]
pub struct MessagePickupHandler {}

#[async_trait]
impl DidcommHandler for MessagePickupHandler {
    async fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>> {
        let key = key.clone().unwrap();
        let did = key.get_did_document(CONFIG_LD_PUBLIC).id;
        match request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/messagepickup/1.0/")
        {
            true => {
                let response = {
                    let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
                        connections.unwrap().clone();
                    let message = MessagePickupResponseBuilder::new()
                        .message(request.clone())
                        .did(did)
                        .connections(&connections)
                        .build()
                        .await;
                    drop(connections);
                    message
                };

                match response {
                    Ok(response) => {
                        let response = match sign_and_encrypt_message(request, &response, key) {
                            Ok(response) => response,
                            Err(error) => serde_json::to_value(error.to_string()).unwrap(),
                        };

                        Ok(HandlerResponse::Response(response))
                    }
                    Err(_) => Ok(HandlerResponse::Processed),
                }
            }
            _ => Ok(HandlerResponse::Skipped),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::Connections;
    use did_key::{generate, X25519KeyPair};

    #[tokio::test]
    async fn test_build_status_request() {
        let response = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .await
            .unwrap();
        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_build_status() {
        let mut request = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .await
            .unwrap();
        request = request.from("did:test");

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );

        let mut connections = Connections::default();
        let message = Message::new().to(&["did:test"]);
        connections.insert_message(message).await;

        let response = MessagePickupResponseBuilder::new()
            .connections(&Arc::new(Mutex::new(Box::new(connections))))
            .message(request)
            .did("did:test".to_string())
            .build()
            .await
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status"
        );
        let (_, message_count) = response
            .get_application_params()
            .filter(|(key, _)| *key == "message_count")
            .next()
            .unwrap();
        assert_eq!(message_count, "1");
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

    #[tokio::test]
    async fn test_build_batch() {
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
        connections.insert_message(message1).await;
        let message2 = Message::new().to(&["did:test"]);
        connections.insert_message(message2).await;

        assert_eq!(
            connections
                .get("did:test".to_string())
                .await
                .unwrap()
                .messages
                .len(),
            2
        );

        let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
            Arc::new(Mutex::new(Box::new(connections)));

        let response = MessagePickupResponseBuilder::new()
            .connections(&connections)
            .message(request)
            .did("did:test".to_string())
            .build_batch()
            .await
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/batch"
        );

        assert!(response.get_attachments().next().is_some());

        assert_eq!(
            connections
                .try_lock()
                .unwrap()
                .get("did:test".to_string())
                .await
                .unwrap()
                .messages
                .len(),
            1
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_ask_too_many_batches() {
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

        let connections = Connections::default();

        assert!(connections.get("did:test".to_string()).await.is_none());

        let connections: Arc<Mutex<Box<dyn ConnectionStorage>>> =
            Arc::new(Mutex::new(Box::new(connections)));

        let response = MessagePickupResponseBuilder::new()
            .connections(&connections)
            .message(request)
            .did("did:test".to_string())
            .build_batch()
            .await
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/batch"
        );

        assert!(response.get_attachments().next().is_none());

        assert!(connections
            .try_lock()
            .unwrap()
            .get("did:test".to_string())
            .await
            .is_none());

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let request = MessagePickupResponseBuilder::new()
            .did("did:test".to_string())
            .build()
            .await
            .unwrap();
        let request = request.from(&key.get_did_document(Default::default()).id);

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/messagepickup/1.0/status-request"
        );
        let handler = MessagePickupHandler::default();
        let response = handler
            .handle(
                &request,
                Some(&key),
                Some(&Arc::new(Mutex::new(Box::new(Connections::default())))),
            )
            .await;
        assert_ne!(response.unwrap(), HandlerResponse::Skipped);
    }
}
