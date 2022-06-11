use base58::{FromBase58, ToBase58};
use did_key::{generate, KeyMaterial, KeyPair, X25519KeyPair};

pub struct Wallet {
    pub seed: String,
}

impl Default for Wallet {
    fn default() -> Self {
        let key = generate::<X25519KeyPair>(None);
        let seed = key.private_key_bytes().to_base58();
        Wallet::new(Some(seed))
    }
}

impl Wallet {
    pub fn new(seed: Option<String>) -> Self {
        match seed {
            Some(seed) => Wallet { seed },
            _ => Wallet::default(),
        }
    }

    pub fn did_key(&self) -> KeyPair {
        generate::<X25519KeyPair>(Some(&self.seed.from_base58().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let wallet = Wallet::default();
        assert_ne!(wallet.seed, "");
    }

    #[test]
    fn test_new() {
        let wallet1 = Wallet::default();
        let wallet2 = Wallet::new(Some(wallet1.seed.to_string()));
        assert_eq!(wallet1.seed, wallet2.seed);

        let wallet = Wallet::new(None);
        assert_ne!(wallet.seed, "");
    }

    #[test]
    fn test_did_key() {
        let wallet = Wallet::default();
        assert_ne!(wallet.did_key().private_key_bytes(), Vec::<u8>::new());
    }
}
