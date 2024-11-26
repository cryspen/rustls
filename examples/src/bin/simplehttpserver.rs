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

use log::{log, Level};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, DEFAULT_VERSIONS};

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

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_connection(stream, config.clone()) {
                    log!(Level::Error, "error handling connection: {err}");
                }
            }
            Err(err) => {
                log!(Level::Error, "error in incoming stream: {err}");
            }
        }
    }

    Ok(())
}

fn handle_connection(
    mut stream: std::net::TcpStream,
    config: ServerConfig,
) -> Result<(), HttpsServerError> {
    let mut req_buf = [0; 128];

    let mut conn = rustls::ServerConnection::new(Arc::new(config.clone()))
        .map_err(HttpsServerError::Rustls)?;

    conn.complete_io(&mut stream)
        .map_err(HttpsServerError::Io)?;

    let len = loop {
        match conn.reader().read(&mut req_buf) {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                conn.complete_io(&mut stream)
                    .map_err(HttpsServerError::Io)?;
            }
            Err(err) => return Err(HttpsServerError::Io(err)),
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

    conn.complete_io(&mut stream)
        .map_err(HttpsServerError::Io)?;

    Ok(())
}

enum HttpsServerError {
    Io(std::io::Error),
    Rustls(rustls::Error),
}

impl std::fmt::Display for HttpsServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpsServerError::Io(err) => write!(f, "io error: {err}"),
            HttpsServerError::Rustls(err) => write!(f, "rustls error: {err}"),
        }
    }
}
