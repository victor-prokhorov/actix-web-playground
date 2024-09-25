use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader};

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
