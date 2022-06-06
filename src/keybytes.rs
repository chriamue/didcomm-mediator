use did_key::{KeyMaterial, KeyPair};

pub trait KeyBytes {
    fn private_key(&self) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
}

impl KeyBytes for KeyPair {
    fn private_key(&self) -> Vec<u8> {
        self.private_key_bytes()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::{generate, Ed25519KeyPair, KeyMaterial, X25519KeyPair};

    #[test]
    fn test_private_key() {
        let seed = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";

        let private = seed.from_base58().unwrap();

        let keypair = generate::<Ed25519KeyPair>(Some(&private));
        assert_eq!(keypair.private_key_bytes(), keypair.private_key());
    }

    #[test]
    fn test_public_key() {
        let seed = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";

        let private = seed.from_base58().unwrap();

        let keypair = generate::<X25519KeyPair>(Some(&private));
        assert_eq!(keypair.public_key_bytes(), keypair.public_key());
    }
}
