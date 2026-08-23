use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod protocol;
mod socks5;
use protocol::*;
use socks5::handle_socks5_handshake;

#[derive(Parser)]
#[command(name = "rdp-vless-tunnel")]
#[command(about = "Synthesized RDP-Framed VLESS Obfuscation Proxy")]
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
    },
    Client {
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        listen: String,

        #[arg(short, long, default_value = "127.0.0.1:3389")]
        server: String,

        #[arg(short, long, default_value = "a1b2c3d4-e5f6-7890-abcd-ef1234567890")]
        uuid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { listen, uuid } => run_server(&listen, &uuid).await,
        Commands::Client { listen, server, uuid } => run_client(&listen, &server, &uuid).await,
    }
}

async fn run_server(listen_addr: &str, allowed_uuid: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("[+] RDP-Framed Proxy Server listening on {}", listen_addr);

    let tls_acceptor = create_rdp_tls_acceptor()?;
    let allowed_uuid = Arc::new(allowed_uuid.to_string());

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let allowed_uuid = allowed_uuid.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(stream, tls_acceptor, &allowed_uuid).await {
                eprintln!("[-] Client connection error ({}) : {:?}", peer_addr, e);
            }
        });
    }
}

async fn handle_server_conn(mut stream: TcpStream, acceptor: TlsAcceptor, allowed_uuid: &str) -> Result<()> {
    // 1. Pre-TLS Connection Negotiation
    let _cr_body = recv_rdp_cr(&mut stream).await?;
    stream.write_all(RDP_NEG_CC).await?;
    stream.flush().await?;

    // 2. TLS Upgrade
    let mut tls_stream = acceptor.accept(stream).await?;
    let mut rbuf = Vec::with_capacity(4096);

    // 3. CredSSP Handshake (Synthetic)
    recv_ber_frame(&mut tls_stream, &mut rbuf).await?; // Client NTLMSSP Negotiate
    
    let mut server_nonce = [0u8; 8];
    server_nonce.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[0..8]);
    
    tls_stream.write_all(&create_ntlmssp_challenge(&server_nonce)).await?;
    tls_stream.flush().await?;

    recv_ber_frame(&mut tls_stream, &mut rbuf).await?; // Client NTLMSSP Auth
    if rbuf.is_empty() {
        bail!("Empty NTLM authentication payload received");
    }

    tls_stream.write_all(&create_credssp_ack()).await?;
    tls_stream.flush().await?;

    // 4. MCS Control Sequences
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // MCS Connect Initial
    send_tpkt_x224(&mut tls_stream, MCS_CONNECT_RESPONSE).await?;

    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // Erect Domain
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // Attach User
    
    let user_id = 1001u16;
    let channel_id = 0x03ebu16;
    send_tpkt_x224(&mut tls_stream, &create_mcs_attach_user_confirm(user_id)).await?;

    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // Channel Join Request
    send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_confirm(user_id, channel_id)).await?;

    // 5. RDP Session Handshake
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // Client Info
    send_tpkt_x224(&mut tls_stream, RDP_DEMAND_ACTIVE_PDU).await?;
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?; // Confirm Active

    // 6. Masked VLESS Header Parsing
    let (s, e) = recv_rdp_vc_pdu(&mut tls_stream, &mut rbuf).await?;
    let parsed_uuid = uuid::Uuid::parse_str(allowed_uuid)?;
    let header = VlessHeader::parse_masked(&rbuf[s..e], &parsed_uuid)?;

    let target_addr = if header.target_host.contains(':') && !header.target_host.starts_with('[') {
        format!("[{}]:{}", header.target_host, header.target_port)
    } else {
        format!("{}:{}", header.target_host, header.target_port)
    };

    println!("[+] Establishing outbound proxy stream to: {}", target_addr);
    let outbound = TcpStream::connect(&target_addr).await?;

    // 7. Proxy Duplex
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut out_reader, mut out_writer) = outbound.into_split();

    let inbound_task = async move {
        let mut buf = Vec::with_capacity(16384);
        loop {
            match recv_rdp_vc_pdu(&mut tls_reader, &mut buf).await {
                Ok((s, e)) if e > s => {
                    if out_writer.write_all(&buf[s..e]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = out_writer.shutdown().await;
    };

    let outbound_task = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match out_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send_rdp_vc_pdu(&mut tls_writer, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
    };

    tokio::select! {
        _ = inbound_task => {},
        _ = outbound_task => {},
    }

    Ok(())
}

async fn run_client(local_listen: &str, remote_server: &str, user_uuid: &str) -> Result<()> {
    let listener = TcpListener::bind(local_listen).await?;
    println!("[+] SOCKS5 listener running on {}", local_listen);

    let tls_connector = create_insecure_connector();
    let remote_server = Arc::new(remote_server.to_string());
    let user_uuid = Arc::new(user_uuid.to_string());

    loop {
        let (local_stream, _) = listener.accept().await?;
        let connector = tls_connector.clone();
        let remote_server = remote_server.clone();
        let user_uuid = user_uuid.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client_conn(local_stream, connector, &remote_server, &user_uuid).await {
                eprintln!("[-] Client proxy error: {:?}", e);
            }
        });
    }
}

async fn handle_client_conn(
    mut local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    user_uuid: &str,
) -> Result<()> {
    let target = handle_socks5_handshake(&mut local_stream).await?;

    let mut remote = TcpStream::connect(server_addr).await?;
    remote.write_all(&create_rdp_cr()).await?;
    remote.flush().await?;

    let mut cc_buf = [0u8; 19];
    remote.read_exact(&mut cc_buf).await?;
    if cc_buf[..4] != RDP_NEG_CC[..4] {
        bail!("RDP Connection Negotiation failed");
    }

    let domain = ServerName::try_from("win-serv2022-dc.local")?.to_owned();
    let mut tls_stream = connector.connect(domain, remote).await?;
    let mut rbuf = Vec::with_capacity(4096);

    // CredSSP Exchange
    tls_stream.write_all(&create_ntlmssp_negotiate()).await?;
    tls_stream.flush().await?;
    recv_ber_frame(&mut tls_stream, &mut rbuf).await?;

    let server_nonce = extract_ntlmssp_challenge(&rbuf)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract NTLM challenge from server"))?;

    tls_stream.write_all(&create_ntlmssp_auth(&server_nonce)).await?;
    tls_stream.flush().await?;
    recv_ber_frame(&mut tls_stream, &mut rbuf).await?;

    // MCS Sequences
    send_tpkt_x224(&mut tls_stream, MCS_CONNECT_INITIAL).await?;
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?;

    send_tpkt_x224(&mut tls_stream, MCS_ERECT_DOMAIN_REQ).await?;
    send_tpkt_x224(&mut tls_stream, MCS_ATTACH_USER_REQ).await?;
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?;

    let user_id = 1001u16;
    let channel_id = 0x03ebu16;
    send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_req(user_id, channel_id)).await?;
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?;

    // Session Exchange
    send_tpkt_x224(&mut tls_stream, RDP_CLIENT_INFO_PDU).await?;
    recv_tpkt_x224(&mut tls_stream, &mut rbuf).await?;
    send_tpkt_x224(&mut tls_stream, RDP_CONFIRM_ACTIVE_PDU).await?;

    // Encapsulated & Masked VLESS Header
    let vless = VlessHeader {
        uuid: uuid::Uuid::parse_str(user_uuid)?,
        target_host: target.host,
        target_port: target.port,
    };
    send_rdp_vc_pdu(&mut tls_stream, &vless.serialize_masked()?).await?;

    // Duplex Stream
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut local_reader, mut local_writer) = local_stream.into_split();

    let inbound = async move {
        let mut buf = Vec::with_capacity(16384);
        loop {
            // Corrected: passing mutable reference &mut buf
            match recv_rdp_vc_pdu(&mut tls_reader, &mut buf).await {
                Ok((s, e)) if e > s => {
                    if local_writer.write_all(&buf[s..e]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = local_writer.shutdown().await;
    };

    let outbound = async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match local_reader.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send_rdp_vc_pdu(&mut tls_writer, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
    };

    tokio::select! {
        _ = inbound => {},
        _ = outbound => {},
    }

    Ok(())
}

fn create_rdp_tls_acceptor() -> Result<TlsAcceptor> {
    let san = vec!["win-serv2022-dc.local".to_string(), "localhost".to_string()];
    let cert = generate_simple_self_signed(san)?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    config.alpn_protocols = vec![];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn create_insecure_connector() -> TlsConnector {
    #[derive(Debug)]
    struct DangerousVerifier;
    impl ServerCertVerifier for DangerousVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![];
    TlsConnector::from(Arc::new(config))
}