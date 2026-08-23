use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Maximum BER frame size to prevent memory exhaustion attacks
const MAX_BER_FRAME: usize = 1024 * 1024; // 1 MiB
// Maximum TPKT frame size
const MAX_TPKT_FRAME: usize = 65535;

// --- BER ENCODING UTILITIES ---

pub fn encode_ber_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len <= 255 {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 65535 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else if len <= 16_777_215 {
        out.push(0x83);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x84);
        out.push(((len >> 24) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

pub fn wrap_ber_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_ber_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

pub async fn recv_ber_frame<R: AsyncReadExt + Unpin>(stream: &mut R, buf: &mut Vec<u8>) -> Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x30 {
        bail!("Invalid BER sequence tag: {:#04x}, expected 0x30", header[0]);
    }

    let body_len = if header[1] < 0x80 {
        header[1] as usize
    } else if header[1] == 0x81 {
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await?;
        len_buf[0] as usize
    } else if header[1] == 0x82 {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        u16::from_be_bytes(len_buf) as usize
    } else if header[1] == 0x83 {
        let mut len_buf = [0u8; 3];
        stream.read_exact(&mut len_buf).await?;
        ((len_buf[0] as usize) << 16) | ((len_buf[1] as usize) << 8) | (len_buf[2] as usize)
    } else if header[1] == 0x84 {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        u32::from_be_bytes(len_buf) as usize
    } else {
        bail!("Unsupported BER length format: {:#04x}", header[1]);
    };

    // Prevent unbounded memory allocation attacks
    if body_len > MAX_BER_FRAME {
        bail!("BER frame too large: {} bytes (max: {})", body_len, MAX_BER_FRAME);
    }

    buf.resize(body_len, 0);
    stream.read_exact(buf).await?;
    Ok(())
}

// --- LAYER 1: RDP CONNECTION REQUEST & CONFIRM ---

pub fn create_rdp_cr() -> Vec<u8> {
    let cookie = b"Cookie: mstshash=Administrator\r\n";
    let neg_req: [u8; 8] = [
        0x01, 0x00, // TYPE_RDP_NEG_REQ
        0x08, 0x00, // Length = 8
        0x03, 0x00, 0x00, 0x00, // requestedProtocols = PROTOCOL_SSL | PROTOCOL_HYBRID
    ];

    let fixed_x224_len = 6;
    let li = (fixed_x224_len + neg_req.len() + cookie.len()) as u8;

    let mut x224 = Vec::with_capacity(1 + li as usize);
    x224.push(li);
    x224.push(0xe0); // Connection Request (CR)
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
    0x03, 0x00, 0x00, 0x13, // TPKT Header (Length 19)
    0x0e,                   // X.224 Length Indicator (14 bytes)
    0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // Connection Confirm
    0x02, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_RSP (PROTOCOL_SSL | PROTOCOL_HYBRID)
];

pub async fn recv_rdp_cr<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut tpkt_hdr = [0u8; 4];
    stream.read_exact(&mut tpkt_hdr).await?;
    if tpkt_hdr[0] != 0x03 {
        bail!("Invalid TPKT version in RDP Connection Request: {:#04x}", tpkt_hdr[0]);
    }
    let total_len = u16::from_be_bytes([tpkt_hdr[2], tpkt_hdr[3]]) as usize;
    if total_len < 19 {
        bail!("TPKT Connection Request frame too short: {}", total_len);
    }
    if total_len > MAX_TPKT_FRAME {
        bail!("TPKT Connection Request frame too large: {}", total_len);
    }
    let body_len = total_len - 4;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    let li = body[0] as usize;
    if body.len() < li + 1 {
        bail!("X.224 Length Indicator exceeds total frame length");
    }
    if body[1] != 0xe0 {
        bail!("Invalid X.224 Connection Request indicator: {:#04x}", body[1]);
    }

    // Validate RDP_NEG_REQ at the expected fixed offset after X.224 header
    // X.224 CR: LI (1 byte) + CD (1 byte) + reserved (5 bytes) = 7 bytes
    // RDP_NEG_REQ starts at offset 7 + cookie_length (if present)
    // We search for it at a reasonable position, but validate structure strictly
    let rdp_neg_req_marker = [0x01u8, 0x00, 0x08, 0x00];
    let mut found_pos = None;
    
    // Search only in valid range (after X.224 header, before end of body)
    for i in 7..body.len().saturating_sub(4) {
        if body[i..i+4] == rdp_neg_req_marker {
            found_pos = Some(i);
            break;
        }
    }

    if let Some(pos) = found_pos {
        // Verify we have enough bytes for the full RDP_NEG_REQ structure
        if body.len() >= pos + 8 {
            let requested_protocols = u32::from_le_bytes([
                body[pos + 4],
                body[pos + 5],
                body[pos + 6],
                body[pos + 7],
            ]);
            if requested_protocols & 0x03 == 0 {
                bail!("Client failed to request TLS/CredSSP protocol security");
            }
        } else {
            bail!("RDP_NEG_REQ structure truncated");
        }
    } else {
        bail!("Missing required RDP_NEG_REQ structure inside Connection Request");
    }

    Ok(body)
}

// --- LAYER 2: CredSSP NLA & ASN.1 / NTLMSSP MESSAGES ---

/// Wrap NTLMSSP data in a valid CredSSP TSRequest structure.
/// Per MS-CSSP Section 2.2.1:
/// - version [0] IMPLICIT INTEGER
/// - negoTokens [1] IMPLICIT OCTET STRING (primitive, tag 0x81)
pub fn wrap_credssp_ts_request(ntlmssp_data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();

    // version [0] IMPLICIT INTEGER – typically A0 03 02 01 02
    body.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);

    // negoTokens [1] IMPLICIT OCTET STRING (primitive context tag 0x81)
    body.extend_from_slice(&wrap_ber_tag(0x81, ntlmssp_data));

    wrap_ber_tag(0x30, &body)
}

pub fn create_ntlmssp_negotiate() -> Vec<u8> {
    let mut ntlm = Vec::with_capacity(40);
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Type 1 Negotiate
    ntlm.extend_from_slice(&[0x05, 0xb2, 0x89, 0xe2]); // Negotiate Flags

    ntlm.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00]);
    ntlm.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00]);
    ntlm.extend_from_slice(&[10, 0, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f]);

    wrap_credssp_ts_request(&ntlm)
}

pub fn create_ntlmssp_challenge(server_nonce: &[u8; 8]) -> Vec<u8> {
    let domain_utf16: Vec<u8> = "WORKGROUP".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let domain_len = domain_utf16.len() as u16;

    let mut target_info = Vec::new();
    target_info.extend_from_slice(&2u16.to_le_bytes());
    target_info.extend_from_slice(&domain_len.to_le_bytes());
    target_info.extend_from_slice(&domain_utf16);
    target_info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let header_len: u32 = 56;
    let target_name_offset = header_len;
    let target_info_offset = target_name_offset + domain_len as u32;

    let mut ntlm = Vec::with_capacity(header_len as usize + domain_utf16.len() + target_info.len());
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // Type 2 Challenge

    ntlm.extend_from_slice(&domain_len.to_le_bytes());
    ntlm.extend_from_slice(&domain_len.to_le_bytes());
    ntlm.extend_from_slice(&target_name_offset.to_le_bytes());

    ntlm.extend_from_slice(&[0x05, 0x82, 0x89, 0xe2]);
    ntlm.extend_from_slice(server_nonce);
    ntlm.extend_from_slice(&[0x00; 8]);

    ntlm.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&target_info_offset.to_le_bytes());

    ntlm.extend_from_slice(&[10, 0, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f]);

    ntlm.extend_from_slice(&domain_utf16);
    ntlm.extend_from_slice(&target_info);

    wrap_credssp_ts_request(&ntlm)
}

pub fn extract_ntlmssp_challenge(data: &[u8]) -> Option<[u8; 8]> {
    let pos = data.windows(8).position(|w| w == &b"NTLMSSP\0"[..])?;
    if data.len() >= pos + 32 {
        let mut challenge = [0u8; 8];
        challenge.copy_from_slice(&data[pos + 24..pos + 32]);
        Some(challenge)
    } else {
        None
    }
}

pub fn create_ntlmssp_auth(server_nonce: &[u8; 8]) -> Vec<u8> {
    let domain: Vec<u8> = "WORKGROUP".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let user: Vec<u8> = "Administrator".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let workstation: Vec<u8> = "CLIENT".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    let mut lm_resp = vec![0u8; 24];
    lm_resp[16..24].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let mut nt_resp = Vec::with_capacity(48);
    let mut proof = [0u8; 16];
    for i in 0..8 {
        proof[i] = server_nonce[i] ^ 0xAA;
        proof[i + 8] = server_nonce[i] ^ 0x55;
    }
    nt_resp.extend_from_slice(&proof);
    nt_resp.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    nt_resp.extend_from_slice(&0u64.to_le_bytes());
    nt_resp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]);
    nt_resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let header_len: u32 = 72;
    let lm_offset = header_len;
    let nt_offset = lm_offset + lm_resp.len() as u32;
    let domain_offset = nt_offset + nt_resp.len() as u32;
    let user_offset = domain_offset + domain.len() as u32;
    let workstation_offset = user_offset + user.len() as u32;
    let session_key_offset = workstation_offset + workstation.len() as u32;

    let mut ntlm = Vec::with_capacity(session_key_offset as usize);
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // Type 3 Authenticate

    ntlm.extend_from_slice(&(lm_resp.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(lm_resp.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&lm_offset.to_le_bytes());

    ntlm.extend_from_slice(&(nt_resp.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(nt_resp.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&nt_offset.to_le_bytes());

    ntlm.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&domain_offset.to_le_bytes());

    ntlm.extend_from_slice(&(user.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(user.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&user_offset.to_le_bytes());

    ntlm.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
    ntlm.extend_from_slice(&workstation_offset.to_le_bytes());

    ntlm.extend_from_slice(&0u16.to_le_bytes());
    ntlm.extend_from_slice(&0u16.to_le_bytes());
    ntlm.extend_from_slice(&session_key_offset.to_le_bytes());

    ntlm.extend_from_slice(&[0x05, 0x82, 0x89, 0xe2]);
    ntlm.extend_from_slice(&[10, 0, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f]);

    ntlm.extend_from_slice(&lm_resp);
    ntlm.extend_from_slice(&nt_resp);
    ntlm.extend_from_slice(&domain);
    ntlm.extend_from_slice(&user);
    ntlm.extend_from_slice(&workstation);

    wrap_credssp_ts_request(&ntlm)
}

pub fn create_credssp_ack() -> Vec<u8> {
    let token_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let pub_key_auth = wrap_ber_tag(0x83, &token_bytes); // Primitive context tag [3]
    let mut body = wrap_ber_tag(0xa0, &[0x02, 0x01, 0x02]);
    body.extend_from_slice(&pub_key_auth);
    wrap_ber_tag(0x30, &body)
}

// --- LAYER 3: TPKT + X.224 MCS CONTROL FRAMING ---

pub async fn send_tpkt_x224<W: AsyncWriteExt + Unpin>(stream: &mut W, payload: &[u8]) -> Result<()> {
    let total_len = payload.len() + 7;
    if total_len > 65535 {
        bail!("TPKT/X.224 payload size exceeds 65535 byte framing limit");
    }

    let mut header = [0u8; 7];
    header[0] = 0x03;
    header[1] = 0x00;
    let len_bytes = (total_len as u16).to_be_bytes();
    header[2] = len_bytes[0];
    header[3] = len_bytes[1];
    header[4] = 0x02;
    header[5] = 0xf0;
    header[6] = 0x80;

    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv_tpkt_x224<R: AsyncReadExt + Unpin>(stream: &mut R, buf: &mut Vec<u8>) -> Result<()> {
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x03 || header[4] != 0x02 || header[5] != 0xf0 || header[6] != 0x80 {
        bail!("Malformed TPKT/X.224 header structure");
    }
    let pdu_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if pdu_len < 7 {
        bail!("TPKT frame length underflow");
    }
    // Enforce maximum TPKT frame size
    if pdu_len > MAX_TPKT_FRAME {
        bail!("TPKT frame too large: {}", pdu_len);
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

pub const MCS_CONNECT_INITIAL: &[u8] = &[
    0x7f, 0x65, 0x82, 0x01, 0x04, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff, 0x30,
    0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01,
    0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00,
    0x44, 0x75, 0x63, 0x61, 0x81, 0x30, 0x00, 0x01, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0x00,
];

pub const MCS_CONNECT_RESPONSE: &[u8] = &[
    0x7f, 0x66, 0x0e, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x05, 0x02, 0x01, 0x01, 0x02,
    0x01, 0x01,
];

pub const MCS_ERECT_DOMAIN_REQ: &[u8] = &[0x04, 0x01, 0x00, 0x01, 0x00, 0x01];
pub const MCS_ATTACH_USER_REQ: &[u8] = &[0x28];

pub const RDP_CLIENT_INFO_PDU: &[u8] = &[
    0x64, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
    0x00, 0x80, 0x07, 0x38, 0x04, 0x00, 0x00, 0x00, 0x00,
];

pub const RDP_DEMAND_ACTIVE_PDU: &[u8] = &[
    0x68, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x10, 0x00, 0x17, 0x00, 0x01, 0x00, 0x04, 0x00, 0x10,
    0x00, 0x00, 0x00,
];

pub const RDP_CONFIRM_ACTIVE_PDU: &[u8] = &[
    0x64, 0x10, 0x01, 0x03, 0xeb, 0x70, 0x10, 0x00, 0x17, 0x00, 0x01, 0x00, 0x04, 0x00, 0x20,
    0x00, 0x00, 0x00,
];

// --- LAYER 4: RDP VIRTUAL CHANNEL PROXY ENCAPSULATION ---

pub async fn send_rdp_vc_pdu<W: AsyncWriteExt + Unpin>(stream: &mut W, payload: &[u8]) -> Result<()> {
    let total_len = payload.len() + 23;
    if total_len > 65535 {
        bail!("Payload size exceeds TPKT frame limit of 65535 bytes");
    }

    let mut header = [0u8; 23];
    header[0] = 0x03;
    header[1] = 0x00;
    let len_bytes = (total_len as u16).to_be_bytes();
    header[2] = len_bytes[0];
    header[3] = len_bytes[1];
    
    header[4] = 0x02;
    header[5] = 0xf0;
    header[6] = 0x80;

    header[7] = 0x64;
    header[8] = 0x10;
    header[9] = 0x01;
    header[10] = 0x03;
    header[11] = 0xeb;
    header[12] = 0x70;

    header[13] = 0x00;
    header[14] = 0x00;

    let payload_len_bytes = (payload.len() as u32).to_le_bytes();
    header[15..19].copy_from_slice(&payload_len_bytes);
    header[19..23].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);

    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv_rdp_vc_pdu<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> Result<(usize, usize)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x03 {
        bail!("Invalid TPKT header version: {:#04x}", header[0]);
    }

    let pdu_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if pdu_len < 23 {
        bail!("Invalid RDP Virtual Channel frame length: {}", pdu_len);
    }

    let body_len = pdu_len - 4;
    buf.resize(body_len, 0);
    stream.read_exact(buf).await?;

    if body_len >= 19 && buf[0] == 0x02 && buf[1] == 0xf0 && buf[2] == 0x80 && buf[3] == 0x64 {
        Ok((19, body_len))
    } else {
        bail!("Malformed RDP Virtual Channel PDU frame");
    }
}

// --- VLESS PROTOCOL HEADER ---

pub struct VlessHeader {
    pub uuid: uuid::Uuid,
    pub target_host: String,
    pub target_port: u16,
}

impl VlessHeader {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let host_bytes = self.target_host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("Target host string exceeds maximum allowable length of 255 bytes");
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
        // Minimum valid VLESS header: 1 version + 16 uuid + 1 host_len + 0 host + 2 port = 20 bytes
        if payload.len() < 20 {
            bail!("Payload too short for VLESS header (min 20 bytes, got {})", payload.len());
        }
        if payload[0] != 0x01 {
            bail!("Unsupported VLESS version");
        }

        let uuid = uuid::Uuid::from_slice(&payload[1..17])?;
        let host_len = payload[17] as usize;

        let rem = &payload[18..];
        if rem.len() < host_len + 2 {
            bail!("Truncated VLESS host or port payload");
        }

        let target_host = String::from_utf8(rem[..host_len].to_vec())?;
        let port_bytes = &rem[host_len..host_len + 2];
        let target_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

        Ok(Self {
            uuid,
            target_host,
            target_port,
        })
    }

    pub fn serialize_masked(&self) -> Result<Vec<u8>> {
        let raw = self.serialize()?;
        let key = self.uuid.as_bytes();
        let masked: Vec<u8> = raw
            .iter()
            .enumerate()
            .map(|(idx, &b)| b ^ key[idx % 16])
            .collect();
        Ok(masked)
    }

    pub fn parse_masked(payload: &[u8], expected_uuid: &uuid::Uuid) -> Result<Self> {
        let key = expected_uuid.as_bytes();
        let unmasked: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(idx, &b)| b ^ key[idx % 16])
            .collect();

        let header = Self::parse(&unmasked)?;
        if header.uuid != *expected_uuid {
            bail!("UUID mismatch after stream unmasking");
        }
        Ok(header)
    }
}