use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Service {
    pub id: String,
    #[serde(rename = "recipientKeys")]
    pub recipient_keys: Vec<String>,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    #[serde(rename = "type")]
    pub typ: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Invitation {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub typ: String,
    pub label: String,
    pub handshake_protocols: Vec<String>,
    pub services: Vec<Service>,
}

impl Invitation {
    pub fn new(keys: Vec<String>, label: String, service_endpoint: String) -> Self {
        Invitation {
            id: Uuid::new_v4().to_string(),
            typ: "https://didcomm.org/out-of-band/1.0/invitation".to_string(),
            label,
            handshake_protocols: vec!["https://didcomm.org/didexchange/1.0".to_string()],
            services: vec![Service {
                id: Uuid::new_v4().to_string(),
                recipient_keys: keys,
                service_endpoint,
                typ: "did-communication".to_string(),
            }],
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct InvitationResponse {
    pub invitation: Invitation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_invitation() {
        let invitation = r#"
        {
            "@id": "949034e0-f1e3-4067-bf2e-ce1ff7a831d4",
            "@type": "https://didcomm.org/out-of-band/1.0/invitation",
            "accept": [
              "didcomm/v2"
            ],
            "handshake_protocols": [
              "https://didcomm.org/didexchange/1.0"
            ],
            "label": "did-planning-poker",
            "services": [
              {
                "id": "2e9e814a-c1e1-416e-a21a-a4182809950c",
                "recipientKeys": [
                  "did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup"
                ],
                "serviceEndpoint": "ws://localhost:8082",
                "type": "did-communication"
              }
            ]
          }
        "#;
        let invitation: Invitation = serde_json::from_str(invitation).unwrap();
        assert_eq!(invitation.services[0].typ, "did-communication");
    }
}
