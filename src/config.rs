use serde::Deserialize;
#[derive(Debug, Default, PartialEq, Deserialize)]
pub struct Config {
    pub ident: String,
    pub ext_hostname: String,
    pub ext_service: String,
    pub key_seed: String,
    pub key: Option<()>,
    pub did: String,
}
