use comb_guard::stun::{binding, binding_request, parse_binding_response};
use std::{net::UdpSocket, time::Duration};
#[test]
fn real_udp_binding_health() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server = std::thread::spawn(move || {
        let mut request = [0; 64];
        let (n, peer) = socket.recv_from(&mut request).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&request[..8], &[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        let mut response = request[..20].to_vec();
        response[0..4].copy_from_slice(&[1, 1, 0, 12]);
        response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
        response.extend_from_slice(&(peer.port() ^ 0x2112).to_be_bytes());
        let std::net::IpAddr::V4(ip) = peer.ip() else {
            panic!()
        };
        response.extend_from_slice(&(u32::from(ip) ^ 0x2112a442).to_be_bytes());
        socket.send_to(&response, peer).unwrap();
    });
    let mapped = binding(address, Duration::from_secs(2)).unwrap();
    assert!(mapped.ip().is_loopback());
    assert_ne!(mapped.port(), 0);
    server.join().unwrap();
}
#[test]
fn rejects_cookie_transaction_and_malformed_attributes() {
    let request = binding_request();
    let tx: [u8; 12] = request[8..20].try_into().unwrap();
    let mut response = request.to_vec();
    response[0..4].copy_from_slice(&[1, 1, 0, 12]);
    response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1, 0x21, 0x13, 0x5e, 0x12, 0xa4, 0x43]);
    assert!(parse_binding_response(&response, &tx).is_ok());
    for index in [0, 2, 4, 8, 23, 25] {
        let mut bad = response.clone();
        bad[index] ^= 0xff;
        assert!(parse_binding_response(&bad, &tx).is_err(), "index {index}");
    }
    assert!(parse_binding_response(&response[..19], &tx).is_err());
    assert!(parse_binding_response(&response[..31], &tx).is_err());
}
