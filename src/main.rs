use anyhow::{bail, Result};
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod protocol;
mod socks5;

use protocol::*;
use socks5::handle_socks5_handshake;

const MAX_CONCURRENT_CONNECTIONS: usize = 2048;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

fn default_cert_path() -> PathBuf {
    PathBuf::from("rdp-tunnel-cert.pem")
}
fn default_key_path() -> PathBuf {
    PathBuf::from("rdp-tunnel-key.pem")
}

fn load_or_create_cert(cert_path: &Path, key_path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next()
            .ok_or_else(|| anyhow::anyhow!("no cert"))??;
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow::anyhow!("no key"))?;
        Ok((cert_der.as_ref().to_vec(), key_der.secret_der().to_vec()))
    } else {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| format!("DESKTOP-{}", rand::random::<u32>() % 10000000));

        let mut params = CertificateParams::new(vec![
    "www.microsoft.com".to_string(),
    hostname.clone(),
])?;
params.distinguished_name.push(DnType::CommonName, "www.microsoft.com");
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        std::fs::write(cert_path, cert.pem().as_bytes())?;
        std::fs::write(key_path, key_pair.serialize_pem().as_bytes())?;

        Ok((cert.der().to_vec(), key_pair.serialize_der()))
    }
}

fn create_tls_acceptor(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<TlsAcceptor> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], PrivateKeyDer::Pkcs8(key_der.into()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn create_tls_connector(cert_der: Vec<u8>) -> Result<TlsConnector> {
    let mut root_store = RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der))?;
    let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Parser)]
#[command(name = "rdp-vless-tunnel", about = "Production RDP-Framed VLESS Proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:3389")]
        listen: String,
        #[arg(short, long, default_value = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")]
        uuid: String,
        #[arg(long, default_value_os_t = default_cert_path())]
        cert: PathBuf,
        #[arg(long, default_value_os_t = default_key_path())]
        key: PathBuf,
    },
    Client {
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        listen: String,
        #[arg(short, long, default_value = "127.0.0.1:3389")]
        server: String,
        #[arg(short, long, default_value = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")]
        uuid: String,
        #[arg(long, default_value = "www.microsoft.com")]
        sni: String,
        #[arg(long, default_value_os_t = default_cert_path())]
        cert: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();
    match cli.command {
        Commands::Server { listen, uuid, cert, key } => run_server(&listen, &uuid, &cert, &key).await,
        Commands::Client { listen, server, uuid, sni, cert } => run_client(&listen, &server, &uuid, &sni, &cert).await,
    }
}

async fn run_server(listen_addr: &str, allowed_uuid: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    let (cert_der, key_der) = load_or_create_cert(cert_path, key_path)?;
    let tls_acceptor = create_tls_acceptor(cert_der, key_der)?;
    let listener = TcpListener::bind(listen_addr).await?;

    info!("RDP-Framed Proxy Server listening on {}", listen_addr);
    let allowed_uuid = Arc::new(uuid::Uuid::parse_str(allowed_uuid)?);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer_addr) = match res {
                    Ok(v) => v,
                    Err(e) => { error!("Accept error: {}", e); continue; }
                };
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { warn!("Server at capacity, dropping {}", peer_addr); drop(stream); continue; }
                };

                let tls_acceptor = tls_acceptor.clone();
                let allowed_uuid = allowed_uuid.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_server_conn(stream, tls_acceptor, &allowed_uuid).await {
                        warn!("Conn closed ({}): {:?}", peer_addr, e);
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received. Exiting...");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_server_conn(mut stream: TcpStream, acceptor: TlsAcceptor, allowed_uuid: &uuid::Uuid) -> Result<()> {
    stream.set_nodelay(true)?;

    let has_tls = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_rdp_cr(&mut stream)).await??;
    if !has_tls {
        let _ = stream.write_all(RDP_NEG_FAILURE).await;
        bail!("Client requested plain RDP fallback");
    }

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), stream.write_all(RDP_NEG_CC)).await??;
    let mut tls_stream = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), acceptor.accept(stream)).await??;

    let mut rbuf = BytesMut::with_capacity(4096);
    let (c2s_key, s2c_key) = derive_directional_keys(allowed_uuid);
    let mut opener = PayloadOpener::new(&c2s_key)?;
    let sealer = PayloadSealer::new(&s2c_key)?;

    // MCS Handshake
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_CONNECT_RESPONSE)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;

    let user_id: u16 = rand::random();
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_attach_user_confirm(user_id))).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;

    let (_client_user_id, channel_id) = parse_mcs_channel_join_req(&rbuf)?;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_confirm(user_id, channel_id))).await??;

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_DEMAND_ACTIVE_PDU)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;

    let decrypted_header = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_rdp_vc_pdu(&mut tls_stream, &mut rbuf, user_id, channel_id, &mut opener)).await??;
    let header = VlessHeader::parse(&decrypted_header)?;

    if header.uuid != *allowed_uuid {
        bail!("Unauthorized UUID attempt");
    }

    let target_addr = format!("{}:{}", header.target_host, header.target_port);
    info!("Opening outbound proxy stream to: {}", target_addr);
    let outbound = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), TcpStream::connect(&target_addr)).await??;
    outbound.set_nodelay(true)?;

    relay_traffic(tls_stream, outbound, user_id, channel_id, opener, sealer).await
}

async fn relay_traffic(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    outbound: TcpStream,
    user_id: u16,
    channel_id: u16,
    mut opener: PayloadOpener,
    mut sealer: PayloadSealer,
) -> Result<()> {
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut out_reader, mut out_writer) = outbound.into_split();

    let mut tls_read_buf = BytesMut::with_capacity(65535);

    let inbound_task = async move {
        loop {
            match recv_rdp_vc_pdu(&mut tls_reader, &mut tls_read_buf, user_id, channel_id, &mut opener).await {
                Ok(payload) => {
                    if out_writer.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = out_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    let outbound_task = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match out_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send_rdp_vc_pdu(&mut tls_writer, user_id, channel_id, &buf[..n], &mut sealer).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    let mut inbound_handle = tokio::spawn(inbound_task);
    let mut outbound_handle = tokio::spawn(outbound_task);

    tokio::select! {
        _ = &mut inbound_handle => outbound_handle.abort(),
        _ = &mut outbound_handle => inbound_handle.abort(),
    }
    Ok(())
}

async fn run_client(
    local_listen: &str,
    remote_server: &str,
    user_uuid: &str,
    sni: &str,
    cert_path: &Path,
) -> Result<()> {
    let cert_pem = std::fs::read(cert_path)?;
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice()).next().ok_or_else(|| anyhow::anyhow!("no cert"))??;
    let tls_connector = create_tls_connector(cert_der.as_ref().to_vec())?;
    let listener = TcpListener::bind(local_listen).await?;

    info!("SOCKS5 listener running on {}", local_listen);
    let remote_server = Arc::new(remote_server.to_string());
    let user_uuid = Arc::new(user_uuid.to_string());
    let sni = Arc::new(sni.to_string());
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (local_stream, _) = match res {
                    Ok(v) => v,
                    Err(e) => { error!("Accept error: {}", e); continue; }
                };
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(local_stream); continue; }
                };

                let connector = tls_connector.clone();
                let remote_server = remote_server.clone();
                let user_uuid = user_uuid.clone();
                let sni = sni.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_client_conn(local_stream, connector, &remote_server, &user_uuid, &sni).await {
                        error!("Client proxy error: {:?}", e);
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

async fn handle_client_conn(
    mut local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    user_uuid: &str,
    sni: &str,
) -> Result<()> {
    local_stream.set_nodelay(true)?;
    let target = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), handle_socks5_handshake(&mut local_stream)).await??;

    let mut remote = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), TcpStream::connect(server_addr)).await??;
    remote.set_nodelay(true)?;

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), remote.write_all(&create_rdp_cr())).await??;

    let mut cc_buf = [0u8; 19];
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), remote.read_exact(&mut cc_buf)).await??;

    let domain = ServerName::try_from(sni.to_string())?.to_owned();
    let mut tls_stream = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), connector.connect(domain, remote)).await??;

    let mut rbuf = BytesMut::with_capacity(4096);
    let target_uuid = uuid::Uuid::parse_str(user_uuid)?;

    let (c2s_key, s2c_key) = derive_directional_keys(&target_uuid);
    let mut sealer = PayloadSealer::new(&c2s_key)?;
    let mut opener = PayloadOpener::new(&s2c_key)?;

    // MCS Handshake
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_CONNECT_INITIAL)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_ERECT_DOMAIN_REQ)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_ATTACH_USER_REQ)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;

    let user_id = parse_mcs_attach_user_confirm(&rbuf)?;
    let channel_id: u16 = rand::random();

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_req(user_id, channel_id))).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_CLIENT_INFO_PDU)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf)).await??;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_CONFIRM_ACTIVE_PDU)).await??;

    let vless = VlessHeader {
        uuid: target_uuid,
        target_host: target.host,
        target_port: target.port,
    };

    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), send_rdp_vc_pdu(&mut tls_stream, user_id, channel_id, &vless.serialize()?, &mut sealer)).await??;

    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut local_reader, mut local_writer) = local_stream.into_split();
    let mut tls_read_buf = BytesMut::with_capacity(65535);

    let inbound = async move {
        loop {
            match recv_rdp_vc_pdu(&mut tls_reader, &mut tls_read_buf, user_id, channel_id, &mut opener).await {
                Ok(payload) => {
                    if local_writer.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = local_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    let outbound = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match local_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send_rdp_vc_pdu(&mut tls_writer, user_id, channel_id, &buf[..n], &mut sealer).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    let mut inbound_handle = tokio::spawn(inbound);
    let mut outbound_handle = tokio::spawn(outbound);

    tokio::select! {
        _ = &mut inbound_handle => outbound_handle.abort(),
        _ = &mut outbound_handle => inbound_handle.abort(),
    }
    Ok(())
}
