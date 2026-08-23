use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Socks5Target {
    pub host: String,
    pub port: u16,
}

pub async fn handle_socks5_handshake<S>(stream: &mut S) -> Result<Socks5Target>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut ver_methods = [0u8; 2];
    stream.read_exact(&mut ver_methods).await?;
    if ver_methods[0] != 0x05 {
        bail!("Only SOCKS5 is supported");
    }

    let num_methods = ver_methods[1] as usize;
    let mut methods = vec![0u8; num_methods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        stream.flush().await?;
        bail!("Client did not offer NO AUTH (0x00) method");
    }

    stream.write_all(&[0x05, 0x00]).await?;
    stream.flush().await?;

    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;

    if req_header[0] != 0x05 || req_header[2] != 0x00 {
        let reply = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = stream.write_all(&reply).await;
        bail!("Invalid SOCKS5 request header");
    }

    if req_header[1] != 0x01 {
        let reply = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = stream.write_all(&reply).await;
        bail!("Only SOCKS5 CONNECT (0x01) command is supported");
    }

    let (host, port) = match req_header[3] {
        0x01 => { // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (
                std::net::Ipv4Addr::from(ip).to_string(),
                u16::from_be_bytes(port_buf),
            )
        }
        0x03 => { // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (
                String::from_utf8(domain)?,
                u16::from_be_bytes(port_buf),
            )
        }
        0x04 => { // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (
                std::net::Ipv6Addr::from(ip).to_string(),
                u16::from_be_bytes(port_buf),
            )
        }
        _ => {
            let reply = [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            let _ = stream.write_all(&reply).await;
            bail!("Unsupported SOCKS5 address type");
        }
    };

    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    stream.flush().await?;

    Ok(Socks5Target { host, port })
}