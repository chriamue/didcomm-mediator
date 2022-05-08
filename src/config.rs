use serde::Deserialize;
#[derive(Default, PartialEq, Deserialize)]
pub struct Config {
    pub ident: String,
    pub ext_hostname: String,
    pub ext_service: String,
    pub key_seed: String,
    pub did: String,
}
