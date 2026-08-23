use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod protocol;
mod socks5;
use protocol::*;
use socks5::handle_socks5_handshake;

// Maximum concurrent connections to prevent resource exhaustion
const MAX_CONCURRENT_CONNECTIONS: usize = 100;
// Default IO timeout in seconds
const IO_TIMEOUT_SECS: u64 = 30;

// Static Certificate Configuration
// Generate a single self-signed cert at startup so the fingerprint is consistent for pinning
// Both client and server must use the SAME certificate/key pair
static STATIC_CERT: once_cell::sync::Lazy<StaticCert> = once_cell::sync::Lazy::new(|| {
    let san = vec!["win-serv2022-dc.local".to_string(), "localhost".to_string()];
    let cert = generate_simple_self_signed(san).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    
    // Compute SHA-256 fingerprint
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(&cert_der);
    let digest = context.finish();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    
    StaticCert {
        cert_der,
        key_der,
        fingerprint,
    }
});

struct StaticCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    fingerprint: [u8; 32],
}

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
    // Parse UUID once to avoid reparsing on every connection
    let parsed_uuid = uuid::Uuid::parse_str(allowed_uuid)?;
    let allowed_uuid = Arc::new(parsed_uuid);
    
    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let allowed_uuid = allowed_uuid.clone();
        let semaphore = semaphore.clone();

        tokio::spawn(async move {
            // Acquire permit before processing connection
            let _permit = match semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // Semaphore closed
            };
            
            if let Err(e) = handle_server_conn(stream, tls_acceptor, &allowed_uuid).await {
                eprintln!("[-] Client connection error ({}) : {:?}", peer_addr, e);
            }
        });
    }
}

async fn handle_server_conn(mut stream: TcpStream, acceptor: TlsAcceptor, allowed_uuid: &uuid::Uuid) -> Result<()> {
    // Set TCP_NODELAY for low latency
    stream.set_nodelay(true)?;
    
    // 1. Pre-TLS Connection Negotiation with timeout
    let _cr_body = timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_rdp_cr(&mut stream))
        .await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), stream.write_all(RDP_NEG_CC)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), stream.flush()).await??;

    // 2. TLS Upgrade with timeout
    let mut tls_stream = timeout(Duration::from_secs(IO_TIMEOUT_SECS), acceptor.accept(stream))
        .await??;
    let mut rbuf = Vec::with_capacity(4096);

    // 3. CredSSP Handshake (Synthetic) with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_ber_frame(&mut tls_stream, &mut rbuf))
        .await??; // Client NTLMSSP Negotiate
    
    let mut server_nonce = [0u8; 8];
    server_nonce.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[0..8]);
    
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.write_all(&create_ntlmssp_challenge(&server_nonce))).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.flush()).await??;

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_ber_frame(&mut tls_stream, &mut rbuf))
        .await??; // Client NTLMSSP Auth
    if rbuf.is_empty() {
        bail!("Empty NTLM authentication payload received");
    }

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.write_all(&create_credssp_ack())).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.flush()).await??;

    // 4. MCS Control Sequences with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // MCS Connect Initial
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_CONNECT_RESPONSE)).await??;

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // Erect Domain
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // Attach User
    
    let user_id = 1001u16;
    let channel_id = 0x03ebu16;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_attach_user_confirm(user_id))).await??;

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // Channel Join Request
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_confirm(user_id, channel_id))).await??;

    // 5. RDP Session Handshake with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // Client Info
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_DEMAND_ACTIVE_PDU)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??; // Confirm Active

    // 6. Masked VLESS Header Parsing with timeout
    let (s, e) = timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_rdp_vc_pdu(&mut tls_stream, &mut rbuf))
        .await??;
    let header = VlessHeader::parse_masked(&rbuf[s..e], allowed_uuid)?;

    let target_addr = if header.target_host.contains(':') && !header.target_host.starts_with('[') {
        format!("[{}]:{}", header.target_host, header.target_port)
    } else {
        format!("{}:{}", header.target_host, header.target_port)
    };

    println!("Establishing outbound proxy stream to: {}", target_addr);
    let outbound = timeout(Duration::from_secs(IO_TIMEOUT_SECS), TcpStream::connect(&target_addr))
        .await??;
    outbound.set_nodelay(true)?;

    // 7. Proxy Duplex with graceful shutdown using abort handles
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut out_reader, mut out_writer) = outbound.into_split();

    let inbound_task = async move {
        let mut buf = Vec::with_capacity(16384);
        loop {
            match timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_rdp_vc_pdu(&mut tls_reader, &mut buf)).await {
                Ok(Ok((s, e))) if e > s => {
                    match timeout(Duration::from_secs(IO_TIMEOUT_SECS), out_writer.write_all(&buf[s..e])).await {
                        Ok(Ok(_)) => {},
                        _ => break,
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
            match timeout(Duration::from_secs(IO_TIMEOUT_SECS), out_reader.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    match timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_rdp_vc_pdu(&mut tls_writer, &buf[..n])).await {
                        Ok(Ok(_)) => {},
                        _ => break,
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    // Use select with AbortHandle to ensure both tasks complete or are cancelled
    let mut inbound_handle = tokio::spawn(inbound_task);
    let mut outbound_handle = tokio::spawn(outbound_task);

    tokio::select! {
        res = &mut inbound_handle => {
            outbound_handle.abort();
            if let Err(e) = res {
                eprintln!("Inbound task error: {:?}", e);
            }
        }
        res = &mut outbound_handle => {
            inbound_handle.abort();
            if let Err(e) = res {
                eprintln!("Outbound task error: {:?}", e);
            }
        }
    }

    Ok(())
}

async fn run_client(local_listen: &str, remote_server: &str, user_uuid: &str) -> Result<()> {
    let listener = TcpListener::bind(local_listen).await?;
    println!("[+] SOCKS5 listener running on {}", local_listen);

    let tls_connector = create_insecure_connector();
    let remote_server = Arc::new(remote_server.to_string());
    let user_uuid = Arc::new(user_uuid.to_string());
    
    // Semaphore to limit concurrent connections on client side too
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let (local_stream, _) = listener.accept().await?;
        let connector = tls_connector.clone();
        let remote_server = remote_server.clone();
        let user_uuid = user_uuid.clone();
        let semaphore = semaphore.clone();

        tokio::spawn(async move {
            // Acquire permit before processing connection
            let _permit = match semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            
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
    // Set TCP_NODELAY for low latency
    local_stream.set_nodelay(true)?;
    
    // Handle SOCKS5 handshake with timeout
    let target = timeout(Duration::from_secs(IO_TIMEOUT_SECS), handle_socks5_handshake(&mut local_stream))
        .await??;

    // Connect to remote server with timeout
    let mut remote = timeout(Duration::from_secs(IO_TIMEOUT_SECS), TcpStream::connect(server_addr))
        .await??;
    remote.set_nodelay(true)?;
    
    // RDP Connection Negotiation with timeout
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), remote.write_all(&create_rdp_cr())).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), remote.flush()).await??;

    let mut cc_buf = [0u8; 19];
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), remote.read_exact(&mut cc_buf))
        .await??;
    if cc_buf[..4] != RDP_NEG_CC[..4] {
        bail!("RDP Connection Negotiation failed");
    }

    let domain = ServerName::try_from("win-serv2022-dc.local")?.to_owned();
    let mut tls_stream = timeout(Duration::from_secs(IO_TIMEOUT_SECS), connector.connect(domain, remote))
        .await??;
    let mut rbuf = Vec::with_capacity(4096);

    // CredSSP Exchange with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.write_all(&create_ntlmssp_negotiate())).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.flush()).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_ber_frame(&mut tls_stream, &mut rbuf))
        .await??;

    let server_nonce = extract_ntlmssp_challenge(&rbuf)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract NTLM challenge from server"))?;

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.write_all(&create_ntlmssp_auth(&server_nonce))).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), tls_stream.flush()).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_ber_frame(&mut tls_stream, &mut rbuf))
        .await??;

    // MCS Sequences with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_CONNECT_INITIAL)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??;

    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_ERECT_DOMAIN_REQ)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, MCS_ATTACH_USER_REQ)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??;

    let user_id = 1001u16;
    let channel_id = 0x03ebu16;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, &create_mcs_channel_join_req(user_id, channel_id))).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??;

    // Session Exchange with timeouts
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_CLIENT_INFO_PDU)).await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_tpkt_x224(&mut tls_stream, &mut rbuf))
        .await??;
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_tpkt_x224(&mut tls_stream, RDP_CONFIRM_ACTIVE_PDU)).await??;

    // Encapsulated & Masked VLESS Header
    let vless = VlessHeader {
        uuid: uuid::Uuid::parse_str(user_uuid)?,
        target_host: target.host,
        target_port: target.port,
    };
    timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_rdp_vc_pdu(&mut tls_stream, &vless.serialize_masked()?)).await??;

    // Duplex Stream with graceful shutdown using abort handles
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (mut local_reader, mut local_writer) = local_stream.into_split();

    let inbound = async move {
        let mut buf = Vec::with_capacity(16384);
        loop {
            match timeout(Duration::from_secs(IO_TIMEOUT_SECS), recv_rdp_vc_pdu(&mut tls_reader, &mut buf)).await {
                Ok(Ok((s, e))) if e > s => {
                    match timeout(Duration::from_secs(IO_TIMEOUT_SECS), local_writer.write_all(&buf[s..e])).await {
                        Ok(Ok(_)) => {},
                        _ => break,
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
            match timeout(Duration::from_secs(IO_TIMEOUT_SECS), local_reader.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    match timeout(Duration::from_secs(IO_TIMEOUT_SECS), send_rdp_vc_pdu(&mut tls_writer, &buf[..n])).await {
                        Ok(Ok(_)) => {},
                        _ => break,
                    }
                }
                _ => break,
            }
        }
        let _ = tls_writer.shutdown().await;
        Result::<()>::Ok(())
    };

    // Use select with AbortHandle to ensure both tasks complete or are cancelled
    let mut inbound_handle = tokio::spawn(inbound);
    let mut outbound_handle = tokio::spawn(outbound);

    tokio::select! {
        res = &mut inbound_handle => {
            outbound_handle.abort();
            if let Err(e) = res {
                eprintln!("Client inbound task error: {:?}", e);
            }
        }
        res = &mut outbound_handle => {
            inbound_handle.abort();
            if let Err(e) = res {
                eprintln!("Client outbound task error: {:?}", e);
            }
        }
    }

    Ok(())
}

fn create_rdp_tls_acceptor() -> Result<TlsAcceptor> {
    let cert_der = CertificateDer::from(STATIC_CERT.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(STATIC_CERT.key_der.clone().into());

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
            end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            // Pin the server certificate by comparing SHA-256 fingerprint
            let mut context = ring::digest::Context::new(&ring::digest::SHA256);
            context.update(end_entity.as_ref());
            let digest = context.finish();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(digest.as_ref());
            
            if hash == STATIC_CERT.fingerprint {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(RustlsError::General("certificate fingerprint mismatch - possible MITM attack".into()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            // Use standard WebPKI signature verification instead of always accepting
            use tokio_rustls::rustls::client::WebPkiServerVerifier;
            use tokio_rustls::rustls::RootCertStore;
            
            // Create a root store with our pinned certificate as the trust anchor
            let mut root_store = RootCertStore::empty();
            root_store.add(CertificateDer::from(STATIC_CERT.cert_der.clone()))?;
            
            let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| RustlsError::General(format!("failed to build verifier: {:?}", e)))?;
            
            verifier.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            // Use standard WebPKI signature verification instead of always accepting
            use tokio_rustls::rustls::client::WebPkiServerVerifier;
            use tokio_rustls::rustls::RootCertStore;
            
            // Create a root store with our pinned certificate as the trust anchor
            let mut root_store = RootCertStore::empty();
            root_store.add(CertificateDer::from(STATIC_CERT.cert_der.clone()))?;
            
            let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| RustlsError::General(format!("failed to build verifier: {:?}", e)))?;
            
            verifier.verify_tls13_signature(message, cert, dss)
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