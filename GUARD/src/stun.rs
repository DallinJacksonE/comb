//! RFC 8489 UDP Binding diagnostic, not an ICE nomination engine.
use crate::{Error, Result};
use rand::RngCore;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub fn binding_request() -> [u8; 20] {
    let mut message = [0; 20];
    message[1] = 1;
    message[4..8].copy_from_slice(&COOKIE);
    rand::thread_rng().fill_bytes(&mut message[8..]);
    message
}
pub fn parse_binding_response(message: &[u8], transaction: &[u8; 12]) -> Result<SocketAddr> {
    let invalid = || Error::Invalid("invalid STUN binding response");
    if message.len() < 20
        || message[..2] != [1, 1]
        || message[4..8] != COOKIE
        || message[8..20] != *transaction
    {
        return Err(invalid());
    }
    let size = u16::from_be_bytes([message[2], message[3]]) as usize;
    if !size.is_multiple_of(4) || size + 20 != message.len() {
        return Err(invalid());
    }
    let mut offset = 20;
    let mut mapped = None;
    while offset < message.len() {
        if offset + 4 > message.len() {
            return Err(invalid());
        }
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let len = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
        offset += 4;
        if offset + len > message.len() {
            return Err(invalid());
        }
        let attr = &message[offset..offset + len];
        if kind == 0x0020 {
            if mapped.is_some() || len < 4 || attr[0] != 0 {
                return Err(invalid());
            }
            let port = u16::from_be_bytes([attr[2], attr[3]]) ^ 0x2112;
            let ip = match (attr[1], len) {
                (1, 8) => IpAddr::V4(Ipv4Addr::new(
                    attr[4] ^ COOKIE[0],
                    attr[5] ^ COOKIE[1],
                    attr[6] ^ COOKIE[2],
                    attr[7] ^ COOKIE[3],
                )),
                (2, 20) => {
                    let mut octets = [0; 16];
                    for i in 0..16 {
                        octets[i] =
                            attr[4 + i] ^ if i < 4 { COOKIE[i] } else { transaction[i - 4] };
                    }
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(invalid()),
            };
            mapped = Some(SocketAddr::new(ip, port));
        }
        offset += (len + 3) & !3;
    }
    if offset != message.len() {
        return Err(invalid());
    }
    mapped.ok_or_else(invalid)
}
/// One request, bounded receive timeout; connected UDP filters replies by source address.
pub fn binding(server: SocketAddr, timeout: Duration) -> Result<SocketAddr> {
    if timeout.is_zero() {
        return Err(Error::Invalid("timeout must be positive"));
    }
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(server)?;
    let request = binding_request();
    socket.send(&request)?;
    let mut response = [0; 65535];
    let n = socket.recv(&mut response)?;
    parse_binding_response(
        &response[..n],
        request[8..20].try_into().expect("fixed transaction length"),
    )
}
