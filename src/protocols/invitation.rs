// https://identity.foundation/didcomm-messaging/spec/#invitation
use crate::service::Service;
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
pub struct InvitationBuilder {
    goal_code: Option<String>,
    goal: Option<String>,
    attachments: Option<Vec<Message>>,
    services: Option<Vec<Service>>,
}

impl InvitationBuilder {
    pub fn new() -> Self {
        InvitationBuilder {
            goal: None,
            goal_code: None,
            attachments: None,
            services: None,
        }
    }

    pub fn goal(&mut self, goal: String) -> &mut Self {
        self.goal = Some(goal);
        self
    }

    pub fn goal_code(&mut self, goal_code: String) -> &mut Self {
        self.goal_code = Some(goal_code);
        self
    }

    pub fn attachments(&mut self, attachments: Vec<Message>) -> &mut Self {
        self.attachments = Some(attachments);
        self
    }

    pub fn services(&mut self, services: Vec<Service>) -> &mut Self {
        self.services = Some(services);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        let body = &json!({"goal": self.goal.as_ref().unwrap(), "goal_code": self.goal_code.as_ref().unwrap(), "accept": [
            "didcomm/v2"
          ]}).to_string();
        let mut attachments: Vec<AttachmentBuilder> = Vec::new();
        if self.attachments.is_some() {
            for attachment in self.attachments.as_ref().unwrap() {
                let id = attachment.get_didcomm_header().id.clone();
                let attachment_json = attachment.clone().as_raw_json().unwrap();
                attachments.push(
                    AttachmentBuilder::new(true).with_id(&id).with_data(
                        AttachmentDataBuilder::new()
                            .with_link("")
                            .with_json(&attachment_json),
                    ),
                );
            }
        }
        let mut message = Message::new().thid(&Uuid::new_v4().to_string());
        if self.services.is_some() {
            message = message.add_header_field(
                "services".to_string(),
                serde_json::to_string(&self.services).unwrap(),
            );
        }
        Ok(message.as_out_of_band_invitation(body, Some(attachments)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_invitation() {
        let dummy = Message::new();

        let response = InvitationBuilder::new()
            .goal("goal".to_string())
            .goal_code("goal_code".to_string())
            .attachments(vec![dummy])
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "\"https://didcomm.org/out-of-band/2.0/invitation\""
        );
        assert!(response.get_attachments().next().is_some());

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
