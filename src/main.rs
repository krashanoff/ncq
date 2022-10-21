use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use s2n_quic::{client::Connect, Client, Server};
use tokio::io::BufReader;

#[derive(Parser)]
#[clap(about, author, version)]
struct Options {
    /// Application protocols to support.
    #[clap(short, long)]
    application_protos: Vec<String>,

    /// TODO: Listen on the socket for connections, rather than send on it.
    #[clap(short, long)]
    listen: bool,

    /// TODO: CLIENT MODE: whether we should open a bidirectional stream.
    #[clap(short, long)]
    bidi: bool,

    /// TODO: Disables checking of certificates.
    #[clap(short, long)]
    insecure: bool,

    /// Path to some certificate stores. For example, your system root CA store.
    #[clap(short, long)]
    cert: PathBuf,

    /// Name of the server to use in QUIC packets.
    #[clap()]
    server_name: String,

    /// Address to listen on or connect to.
    #[clap(value_parser = clap::value_parser!(SocketAddr))]
    address: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Options::parse();

    let tls =
        s2n_quic::provider::tls::rustls::Client::builder().with_certificate(opts.cert.as_path());
    let tls = tls?
        .with_application_protocols(opts.application_protos.iter().map(|s| s.as_str()))?
        .with_key_logging()?
        .build();
    let client = Client::builder()
        .with_tls(tls?)?
        .with_io("0.0.0.0:0")?
        .start()
        .expect("client");

    let mut connection = client
        .connect(Connect::new(opts.address).with_server_name(opts.server_name))
        .await?;
    connection.keep_alive(true)?;

    println!("Opening stream");
    let stream = connection.open_bidirectional_stream().await?;
    let (mut rx, mut tx) = stream.split();
    println!("Opened stream");

    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut rx, &mut stdout).await;
    });

    let mut stdin = BufReader::new(tokio::io::stdin());
    tokio::io::copy(&mut stdin, &mut tx).await?;

    Ok(())
}
