use comb_guard::turn::{CoturnConfig, Deployment};
use std::net::{IpAddr, Ipv4Addr};
fn config() -> CoturnConfig {
    CoturnConfig {
        mode: Deployment::LoopbackTest,
        listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 3478,
        relay_min: 49160,
        relay_max: 49200,
        realm: "comb.example".into(),
        username: "frame".into(),
        password: "a".repeat(40),
    }
}
#[test]
fn missing_executable_is_an_error() {
    assert!(
        comb_guard::turn::CoturnProcess::spawn("/nonexistent/comb-turnserver", &config()).is_err()
    );
}
#[test]
fn process_lifecycle() {
    let mut process = comb_guard::turn::CoturnProcess::spawn("/bin/true", &config()).unwrap();
    for _ in 0..100 {
        if !process.is_running().unwrap() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("true did not exit");
}
#[test]
#[ignore = "requires installed coturn; set COTURN_EXECUTABLE or install turnserver"]
fn installed_coturn_binding_health() {
    let mut c = config();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    c.port = socket.local_addr().unwrap().port();
    drop(socket);
    let executable = std::env::var("COTURN_EXECUTABLE").unwrap_or("turnserver".into());
    let mut process = comb_guard::turn::CoturnProcess::spawn(executable, &c).unwrap();
    for _ in 0..50 {
        assert!(process.is_running().unwrap(), "coturn exited early");
        if comb_guard::stun::binding(
            (std::net::Ipv4Addr::LOCALHOST, c.port).into(),
            std::time::Duration::from_millis(100),
        )
        .is_ok()
        {
            // TURN Allocate without MESSAGE-INTEGRITY must be challenged, never allocated.
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            udp.connect((std::net::Ipv4Addr::LOCALHOST, c.port))
                .unwrap();
            let mut allocate = comb_guard::stun::binding_request().to_vec();
            allocate[1] = 3;
            allocate[3] = 8;
            allocate.extend_from_slice(&[0, 0x19, 0, 4, 17, 0, 0, 0]);
            udp.send(&allocate).unwrap();
            let mut response = [0; 2048];
            let n = udp.recv(&mut response).unwrap();
            assert!(n >= 20);
            assert_eq!(&response[..2], &[1, 0x13]);
            assert_eq!(&response[4..20], &allocate[4..20]);
            assert_eq!(
                u16::from_be_bytes([response[2], response[3]]) as usize + 20,
                n
            );
            let mut offset = 20;
            let mut challenged = false;
            while offset + 4 <= n {
                let kind = u16::from_be_bytes([response[offset], response[offset + 1]]);
                let len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
                offset += 4;
                assert!(offset + len <= n);
                if kind == 9 {
                    assert!(len >= 4);
                    assert_eq!(&response[offset + 2..offset + 4], &[4, 1]);
                    challenged = true;
                }
                offset += (len + 3) & !3;
            }
            assert!(challenged, "expected TURN 401 Unauthorized challenge");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("coturn never answered a validated STUN binding request");
}
#[test]
fn authenticated_safe_config() {
    let c = config();
    let text = c.render().unwrap();
    for option in [
        "lt-cred-mech",
        "user=frame:",
        "no-cli",
        "no-multicast-peers",
        "no-tls",
        "no-dtls",
    ] {
        assert!(text.contains(option));
    }
    assert!(!text.contains("no-auth"));
    assert!(!text.contains("allow-loopback-peers"));
    let mut c = config();
    c.password = "weak".into();
    assert!(c.render().is_err());
    let mut c = config();
    c.username = "frame\nno-auth".into();
    assert!(c.render().is_err());
    let mut c = config();
    c.realm = "realm\nno-auth".into();
    assert!(c.render().is_err());
    let mut c = config();
    c.relay_max = 1;
    assert!(c.render().is_err());
    let mut c = config();
    c.listen_ip = "0.0.0.0".parse().unwrap();
    assert!(c.render().is_err());
    let mut c = config();
    c.mode = Deployment::Public;
    assert!(c.render().is_err());
    c.listen_ip = "8.8.8.8".parse().unwrap();
    let text = c.render().unwrap();
    assert!(text.contains("denied-peer-ip=10.0.0.0-10.255.255.255"));
}
