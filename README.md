# Synthesized RDP-Framed VLESS Proxy Tunnel

An asynchronous Rust TCP proxy that wraps VLESS stream data inside synthetic Remote Desktop Protocol (`MS-RDPBCGR`, `MS-CSSP`, `TPKT`, `X.224`, and `MCS`) wire structures to bypass naive network pattern filters and protocol matchers.

## Scope & Design Strategy

This project operates as an **obfuscated transport tunnel**, not a full Microsoft Windows Terminal Server or CredSSP Active Directory provider:

* **Obfuscation Strategy**: Implements outer binary protocol headers, TPKT lengths, X.224 connection flags, CredSSP BER structures, and RDP virtual channel wrappers so that network traffic resembles RDP session setups.
* **Stream Handling**: Proxies data via SOCKS5 through a custom VLESS header over an encrypted TLS connection wrapped in RDP channel PDUs.
* **Authentication Boundary**: Authentication between client and proxy relies on shared UUID masking across the tunnel header. It does not validate real NTLMv2 hashes or compute HMAC-MD5 responses against a Domain Controller.

## Protocol Stack
graph TD
    A["SOCKS5 Local Client Request<br/><i>(IPv4 / IPv6 / Domain Target)</i>"] --> B["Layer 1: X.224 Connection Request / Confirm Negotiation<br/><i>(Port 3389)</i>"]
    B --> C["Layer 2: TLS Upgrade<br/><i>(TLS 1.2 / 1.3 with RDP SAN certificates)</i>"]
    C --> D["Layer 3: CredSSP Handshake<br/><i>(ASN.1 BER / NTLMSSP Frame Synthetic)</i>"]
    D --> E["Layer 4: MCS Control Sequence<br/><i>(Erect Domain, Attach User, Join)</i>"]
    E --> F["Layer 5: RDP Session Handshake<br/><i>(Client Info, Demand/Confirm)</i>"]
    F --> G["Layer 6: Virtual Channel Framing + UUID Masked VLESS Proxy Header"]


## Setup & Running

### Requirements
* Rust 1.75+ toolchain

### Build
```bash
cargo build --release

Server Execution

Start the proxy endpoint on port 3389:
Bash

./target/release/rdp-vless-tunnel server \
  --listen 0.0.0.0:3389 \
  --uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890

Client Execution

Start the local SOCKS5 proxy pointing to the tunnel server:
Bash

./target/release/rdp-vless-tunnel client \
  --listen 127.0.0.1:1080 \
  --server 192.168.1.100:3389 \
  --uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890

Routing Traffic
Bash

curl -x socks5h://127.0.0.1:1080 [https://ipinfo.io](https://ipinfo.io)
