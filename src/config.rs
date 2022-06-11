use serde::Deserialize;
#[derive(PartialEq, Deserialize)]
pub struct Config {
    pub ident: String,
    pub ext_hostname: String,
    pub ext_service: String,
    pub wallet_path: Option<String>,
    pub wallet_password: Option<String>,
    pub key_seed: Option<String>,
    pub did_key: Option<String>,
    #[cfg(feature = "iota")]
    pub did_iota: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ident: "".to_string(),
            ext_hostname: "".to_string(),
            ext_service: "".to_string(),
            wallet_path: Some("wallet.hold.example".to_string()),
            wallet_password: Some("changeme".to_string()),
            key_seed: Some("4bo9pLUEahsPqerR756HCQ4A9m3fS7WKwUsXru7CSDFd".to_string()),
            did_key: Some("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string()),
            #[cfg(feature = "iota")]
            did_iota: Some("did:iota:6dgiVE6EhCFqEEBDk6CedUq8aeeqQwQeAVSbZz8PgMzi".to_string()),
        }
    }
}
