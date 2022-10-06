use std::{fs::File, io, path::PathBuf, sync::Arc};

use clap::Parser;
use quinn::{ClientConfig, Endpoint, NewConnection};
use rustls::{Certificate, RootCertStore};
use rustls_pemfile::{certs, read_all};
use tokio::io::{stdin, stdout, AsyncBufReadExt, BufReader};

#[derive(Parser)]
#[clap(about, version)]
struct Options {
    #[clap(short, long)]
    cert_store: Vec<PathBuf>,

    #[clap()]
    server_name: String,

    #[clap()]
    hostname: String,

    #[clap()]
    port: u32,
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() {
    let opts = Options::parse();
    let stdin = stdin();
    let stdout = stdout();

    let cert_paths = opts.cert_store;
    let config = ClientConfig::new(Arc::new({
        let mut trust_store = RootCertStore::empty();

        for cert in cert_paths {
            let mut f = io::BufReader::new(File::open(cert).expect("certpath"));
            let c = certs(&mut f).expect("certs");
            trust_store.add_parsable_certificates(&c);
        }

        let mut tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(trust_store)
            .with_no_client_auth();
        let mut tls_config = tls_config.dangerous();
        let proto = "http/0";
        println!("Using proto {}", proto);
        tls_config.set_certificate_verifier(SkipServerVerification::new());
        tls_config.cfg.alpn_protocols = vec![proto.as_bytes().to_vec()];
        tls_config.cfg.clone()
    }));
    let mut e = Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("create endpoint");
    e.set_default_client_config(config);

    println!("connecting to {}:{}", opts.hostname, opts.port);
    let remote = format!("{}:{}", opts.hostname, opts.port)
        .parse()
        .expect("address");
    let NewConnection { connection, .. } = e
        .connect(remote, &opts.server_name)
        .expect("connect")
        .await
        .expect("connect");

    let buf = BufReader::new(stdin);
    let mut lines = buf.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{}", &line);
        connection.send_datagram(line.into()).expect("send");
    }
}
