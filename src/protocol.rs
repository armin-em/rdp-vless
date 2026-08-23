use anyhow::{bail, Context, Result};
use bytes::{BufMut, BytesMut};
use rand::Rng;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::error::Unspecified;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_TPKT_FRAME: usize = 65535;

pub fn derive_directional_keys(uuid: &uuid::Uuid) -> ([u8; 32], [u8; 32]) {
    let mut c2s_input = uuid.as_bytes().to_vec();
    c2s_input.extend_from_slice(b"client_to_server_rdp_vless_v1");
    let c2s_hash = digest(&SHA256, &c2s_input);

    let mut s2c_input = uuid.as_bytes().to_vec();
    s2c_input.extend_from_slice(b"server_to_client_rdp_vless_v1");
    let s2c_hash = digest(&SHA256, &s2c_input);

    let mut c2s_key = [0u8; 32];
    let mut s2c_key = [0u8; 32];
    c2s_key.copy_from_slice(c2s_hash.as_ref());
    s2c_key.copy_from_slice(s2c_hash.as_ref());
    (c2s_key, s2c_key)
}

struct CounterNonceSequence(u128);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.0.to_le_bytes()[..8]);
        self.0 = self.0.checked_add(1).ok_or(Unspecified)?;
        Ok(Nonce::assume_unique_for_key(nonce_bytes))
    }
}

pub struct PayloadSealer {
    sealing_key: SealingKey<CounterNonceSequence>,
}

impl PayloadSealer {
    pub fn new(raw_key: &[u8; 32]) -> Result<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, raw_key)
            .map_err(|_| anyhow::anyhow!("Failed to create sealing key"))?;
        Ok(Self {
            sealing_key: SealingKey::new(unbound, CounterNonceSequence(0)),
        })
    }

    pub fn encrypt_in_place(&mut self, buffer: &mut BytesMut) -> Result<()> {
        let mut in_out = buffer.to_vec();
        self.sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        buffer.clear();
        buffer.extend_from_slice(&in_out);
        Ok(())
    }
}

pub struct PayloadOpener {
    opening_key: OpeningKey<CounterNonceSequence>,
}

impl PayloadOpener {
    pub fn new(raw_key: &[u8; 32]) -> Result<Self> {
        let unbound = UnboundKey::new(&AES_256_GCM, raw_key)
            .map_err(|_| anyhow::anyhow!("Failed to create opening key"))?;
        Ok(Self {
            opening_key: OpeningKey::new(unbound, CounterNonceSequence(0)),
        })
    }

    pub fn decrypt_in_place(&mut self, ciphertext: &mut [u8]) -> Result<usize> {
        let plaintext = self
            .opening_key
            .open_in_place(Aad::empty(), ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
        Ok(plaintext.len())
    }
}

pub fn create_rdp_cr() -> Vec<u8> {
    let cookie = b"Cookie: mstshash=Administrator\r\n";
    let neg_req: [u8; 8] = [0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00];

    let li = (6 + neg_req.len() + cookie.len()) as u8;
    let mut x224 = Vec::with_capacity(1 + li as usize);
    x224.push(li);
    x224.push(0xe0);
    x224.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    x224.extend_from_slice(&neg_req);
    x224.extend_from_slice(cookie);

    let tpkt_len = (x224.len() + 4) as u16;
    let mut cr = Vec::with_capacity(tpkt_len as usize);
    cr.push(0x03);
    cr.push(0x00);
    cr.extend_from_slice(&tpkt_len.to_be_bytes());
    cr.extend_from_slice(&x224);
    cr
}

pub const RDP_NEG_CC: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
];

pub const RDP_NEG_FAILURE: &[u8] = &[
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub async fn recv_rdp_cr<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<bool> {
    let mut tpkt_hdr = [0u8; 4];
    stream.read_exact(&mut tpkt_hdr).await.context("Failed to read TPKT header")?;

    if tpkt_hdr[0] != 0x03 {
        bail!("Invalid TPKT version");
    }

    let total_len = u16::from_be_bytes([tpkt_hdr[2], tpkt_hdr[3]]) as usize;
    if !(11..=MAX_TPKT_FRAME).contains(&total_len) {
        bail!("Invalid TPKT length");
    }

    let mut body = vec![0u8; total_len - 4];
    stream.read_exact(&mut body).await.context("Failed to read TPKT body")?;

    if body.len() < 7 || body[1] != 0xe0 {
        bail!("Invalid X.224 indicator");
    }

    let rdp_neg_marker = [0x01u8, 0x00, 0x08, 0x00];
    if let Some(pos) = body.windows(4).position(|w| w == rdp_neg_marker) {
        if body.len() >= pos + 8 {
            let requested = u32::from_le_bytes([body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]]);
            return Ok(requested & 0x01 != 0);
        }
    }
    Ok(false)
}

pub async fn send_tpkt_x224<W: AsyncWriteExt + Unpin>(stream: &mut W, payload: &[u8]) -> Result<()> {
    let total_len = payload.len() + 7;
    if total_len > MAX_TPKT_FRAME {
        bail!("TPKT payload too large");
    }

    let mut header = [0u8; 7];
    header[0] = 0x03;
    header[1] = 0x00;
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[4] = 0x02;
    header[5] = 0xf0;
    header[6] = 0x80;

    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv_tpkt_x224<R: AsyncReadExt + Unpin>(stream: &mut R, buf: &mut BytesMut) -> Result<()> {
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await.context("Failed to read TPKT/X.224 header")?;

    if header[0] != 0x03 || header[4] != 0x02 || header[5] != 0xf0 || header[6] != 0x80 {
        bail!("Malformed TPKT/X.224 header");
    }

    let pdu_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(7..=MAX_TPKT_FRAME).contains(&pdu_len) {
        bail!("Invalid TPKT length");
    }

    let body_len = pdu_len - 7;
    buf.resize(body_len, 0);
    stream.read_exact(buf).await?;
    Ok(())
}

pub fn create_mcs_attach_user_confirm(user_id: u16) -> Vec<u8> {
    let mut pdu = vec![0x2e, 0x00];
    pdu.extend_from_slice(&user_id.to_be_bytes());
    pdu.extend_from_slice(&[0x10, 0x01]);
    pdu
}

pub fn create_mcs_channel_join_req(user_id: u16, channel_id: u16) -> Vec<u8> {
    let mut pdu = vec![0x38];
    pdu.extend_from_slice(&user_id.to_be_bytes());
    pdu.extend_from_slice(&channel_id.to_be_bytes());
    pdu
}

pub fn create_mcs_channel_join_confirm(user_id: u16, channel_id: u16) -> Vec<u8> {
    let mut pdu = vec![0x3e, 0x00];
    pdu.extend_from_slice(&user_id.to_be_bytes());
    pdu.extend_from_slice(&channel_id.to_be_bytes());
    pdu.extend_from_slice(&channel_id.to_be_bytes());
    pdu
}

pub fn parse_mcs_attach_user_confirm(data: &[u8]) -> Result<u16> {
    if data.len() < 6 || data[0] != 0x2e || data[1] != 0x00 {
        bail!("Invalid MCS Attach User Confirm");
    }
    Ok(u16::from_be_bytes([data[2], data[3]]))
}

pub fn parse_mcs_channel_join_req(data: &[u8]) -> Result<(u16, u16)> {
    if data.len() < 5 || data[0] != 0x38 {
        bail!("Invalid MCS Channel Join Request");
    }
    Ok((u16::from_be_bytes([data[1], data[2]]), u16::from_be_bytes([data[3], data[4]])))
}

pub const MCS_CONNECT_INITIAL: &[u8] = &[
    0x7f, 0x65, 0x82, 0x01, 0x2a, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02,
    0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x08, 0x00,
    0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63, 0x61, 0x81, 0x30, 0x00, 0x01, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0x00,
];

pub const MCS_CONNECT_RESPONSE: &[u8] = &[
    0x7f, 0x66, 0x0e, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
];

pub const MCS_ERECT_DOMAIN_REQ: &[u8] = &[0x04, 0x01, 0x00, 0x01, 0x00, 0x01];
pub const MCS_ATTACH_USER_REQ: &[u8] = &[0x28];

pub const RDP_CLIENT_INFO_PDU: &[u8] = &[
    0x64, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x80, 0x07, 0x38, 0x04,
    0x00, 0x00, 0x00, 0x00,
];

pub const RDP_DEMAND_ACTIVE_PDU: &[u8] = &[
    0x68, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x10, 0x00, 0x17, 0x00, 0x01, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00,
];

pub const RDP_CONFIRM_ACTIVE_PDU: &[u8] = &[
    0x64, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x10, 0x00, 0x17, 0x00, 0x01, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00,
];

pub async fn send_rdp_vc_pdu<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    user_id: u16,
    channel_id: u16,
    payload: &[u8],
    sealer: &mut PayloadSealer,
) -> Result<()> {
    let mut payload_buf = BytesMut::from(payload);
    sealer.encrypt_in_place(&mut payload_buf)?;

    let pad_len = (16 - (payload_buf.len() % 16)) % 16 + rand::thread_rng().gen_range(0..=16);
    let total_vc_data_len = payload_buf.len() + pad_len;
    let total_pdu_len = total_vc_data_len + 27;

    if total_pdu_len > MAX_TPKT_FRAME {
        bail!("Payload exceeds TPKT limit");
    }

    let mut buf = BytesMut::with_capacity(total_pdu_len);
    buf.put_u8(0x03);
    buf.put_u8(0x00);
    buf.put_u16(total_pdu_len as u16);
    buf.put_slice(&[0x02, 0xf0, 0x80, 0x64, 0x10, 0x01, 0x03]);
    buf.put_u16(channel_id);
    buf.put_u16(user_id);
    buf.put_u32_le(total_vc_data_len as u32);
    buf.put_u32_le(0x00000003); // CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST
    buf.put_u32_le(payload_buf.len() as u32);

    buf.put_slice(&payload_buf);
    buf.extend(std::iter::repeat(0).take(pad_len));

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv_rdp_vc_pdu<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut BytesMut,
    expected_user_id: u16,
    expected_channel_id: u16,
    opener: &mut PayloadOpener,
) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x03 {
        bail!("Invalid TPKT header");
    }

    let pdu_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(27..=MAX_TPKT_FRAME).contains(&pdu_len) {
        bail!("Invalid RDP VC PDU length");
    }

    let body_len = pdu_len - 4;
    buf.resize(body_len, 0);
    stream.read_exact(buf).await?;

    if buf[0] != 0x02 || buf[1] != 0xf0 || buf[2] != 0x80 || buf[3] != 0x64 {
        bail!("Malformed RDP Virtual Channel PDU");
    }

    let recv_channel = u16::from_be_bytes([buf[7], buf[8]]);
    let recv_user = u16::from_be_bytes([buf[9], buf[10]]);

    if recv_channel != expected_channel_id || recv_user != expected_user_id {
        bail!("RDP VC PDU ID mismatch");
    }

    let payload_len = u32::from_le_bytes([buf[19], buf[20], buf[21], buf[22]]) as usize;
    let end_offset = 23 + payload_len;

    if end_offset > body_len {
        bail!("RDP VC payload length exceeds frame");
    }

    let cipher_slice = &mut buf[23..end_offset];
    let plain_len = opener.decrypt_in_place(cipher_slice)?;
    Ok(cipher_slice[..plain_len].to_vec())
}

pub struct VlessHeader {
    pub uuid: uuid::Uuid,
    pub target_host: String,
    pub target_port: u16,
}

impl VlessHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let host_bytes = self.target_host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("Target host too long");
        }

        let mut buf = Vec::with_capacity(18 + host_bytes.len() + 2);
        buf.push(0x01);
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.push(host_bytes.len() as u8);
        buf.extend_from_slice(host_bytes);
        buf.extend_from_slice(&self.target_port.to_be_bytes());
        Ok(buf)
    }

    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 20 || payload[0] != 0x01 {
            bail!("Invalid VLESS header");
        }

        let uuid = uuid::Uuid::from_slice(&payload[1..17])?;
        let host_len = payload[17] as usize;
        let rem = &payload[18..];

        if rem.len() < host_len + 2 {
            bail!("Truncated VLESS payload");
        }

        let target_host = String::from_utf8(rem[..host_len].to_vec())?;
        let target_port = u16::from_be_bytes([rem[host_len], rem[host_len + 1]]);

        Ok(Self {
            uuid,
            target_host,
            target_port,
        })
    }
}
