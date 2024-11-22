//! This is the simplest possible https server using rustls:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simplehttpserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::env;
use std::error::Error as StdError;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::DEFAULT_VERSIONS;

fn main() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();

    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
            .with_protocol_versions(DEFAULT_VERSIONS)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut stream, _) = listener.accept()?;

    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;

    conn.complete_io(&mut stream).unwrap();

    let mut req_buf = [0; 128];

    let len = loop {
        match conn.reader().read(&mut req_buf) {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                conn.complete_io(&mut stream).unwrap();
            }
            Err(err) => panic!("{}", err),
            Ok(len) => break len,
        }
    };

    println!(
        "got request: {}",
        String::from_utf8(req_buf[..len].to_vec()).unwrap()
    );

    conn.writer()
        .write_all(b"HTTP/1.1 200 OK\nConnection: close\n\nHello from the server")
        .unwrap();

    conn.complete_io(&mut stream).unwrap();

    Ok(())
}
