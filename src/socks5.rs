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
        bail!("Client did not offer NO AUTH");
    }

    stream.write_all(&[0x05, 0x00]).await?;

    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != 0x05 || req_header[1] != 0x01 {
        bail!("Invalid SOCKS5 request");
    }

    let (host, port) = match req_header[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (std::net::Ipv4Addr::from(ip).to_string(), u16::from_be_bytes(port_buf))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (String::from_utf8(domain)?, u16::from_be_bytes(port_buf))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            (std::net::Ipv6Addr::from(ip).to_string(), u16::from_be_bytes(port_buf))
        }
        _ => bail!("Unsupported address type"),
    };

    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(Socks5Target { host, port })
}
