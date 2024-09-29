use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::{fs::File, io::BufReader};
use typeshare::typeshare;
use uuid::Uuid;

#[path = "./inventory/inventory.rs"]
pub mod inventory;

pub fn load_rustls_config() -> rustls::ServerConfig {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();
    let config = ServerConfig::builder().with_no_client_auth();
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());
    let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().unwrap();
    let mut keys = pkcs8_private_keys(key_file)
        .map(|key| key.map(PrivateKeyDer::Pkcs8))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    if keys.is_empty() {
        std::process::exit(1);
    }
    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}

/// this merges data from "gateway" (which is not really a gateway at this point)
/// and inventory services, represent data to be send to the client, from the repo run
/// ```sh
/// typeshare common --lang=typescript --output-folder=common
/// ```
/// https://github.com/1Password/typeshare/blob/main/docs/src/usage/annotations.md#serialize-as-another-type
#[typeshare]
#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
pub struct Order {
    #[typeshare(serialized_as = "String")]
    id: Uuid,
    /// we loose `Option` by marking manually though
    #[typeshare(serialized_as = "String")]
    user_id: Option<Uuid>,
    #[typeshare(serialized_as = "String")]
    product_id: Uuid,
    available_quantity: i32, // as of today `typeshare-cli` fail on `usize` so `i32` it will be
}
