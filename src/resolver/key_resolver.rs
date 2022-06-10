use did_key::KeyMaterial;
use didcomm_rs::Error;

pub async fn resolve(did: &str) -> Result<Vec<u8>, Error> {
    Ok(did_key::resolve(did).unwrap().public_key_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair};

    #[tokio::test]
    async fn test_resolve() {
        let seed = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";
        let private = seed.from_base58().unwrap();
        let keypair = generate::<X25519KeyPair>(Some(&private));
        let did_doc = keypair.get_did_document(Default::default());
        let did = did_doc.id;

        let resolved = resolve(&did).await.unwrap();
        assert_eq!(resolved, keypair.public_key_bytes());
    }
}
