//! Configuration and lifecycle for the maintained coturn server (not a TURN implementation).
use crate::{Error, Result};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::{Child, Command, Stdio},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    LoopbackTest,
    Public,
}
/// Contains a credential: deliberately does not implement Debug or serialization.
pub struct CoturnConfig {
    pub mode: Deployment,
    pub listen_ip: IpAddr,
    pub port: u16,
    pub relay_min: u16,
    pub relay_max: u16,
    pub realm: String,
    pub username: String,
    pub password: String,
}
/// Owns the child and its mode-0600 temporary config. Drop terminates and reaps it.
pub struct CoturnProcess {
    child: Child,
    _config: tempfile::NamedTempFile,
}
impl CoturnProcess {
    /// Successful spawn does not imply readiness; poll `is_running` and `stun::binding`.
    pub fn spawn(executable: impl AsRef<Path>, config: &CoturnConfig) -> Result<Self> {
        let text = config.render()?;
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(text.as_bytes())?;
        file.as_file().sync_all()?;
        let child = Command::new(executable.as_ref())
            .arg("-c")
            .arg(file.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            child,
            _config: file,
        })
    }
    pub fn is_running(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
}
impl Drop for CoturnProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0))
}
impl CoturnConfig {
    /// Returns sensitive configuration. Persist with mode 0600; never log it.
    pub fn render(&self) -> Result<String> {
        if !token(&self.realm)
            || !token(&self.username)
            || !token(&self.password)
            || self.password.len() < 32
        {
            return Err(Error::Invalid(
                "realm/user/password must be safe tokens; password >=32 chars",
            ));
        }
        if self.port == 0
            || self.relay_min < 1024
            || self.relay_min > self.relay_max
            || (self.relay_min..=self.relay_max).contains(&self.port)
        {
            return Err(Error::Invalid("invalid listener or relay ports"));
        }
        match (self.mode, self.listen_ip) {
            (Deployment::LoopbackTest, ip) if ip.is_loopback() => {}
            (Deployment::Public, IpAddr::V4(ip)) if public_v4(ip) => {}
            _ => {
                return Err(Error::Invalid(
                    "test requires loopback; public requires an explicit public IPv4 address",
                ));
            }
        }
        let mut output = format!(
            "listening-ip={}\nrelay-ip={}\nlistening-port={}\nmin-port={}\nmax-port={}\nrealm={}\nserver-name={}\nlt-cred-mech\nuser={}:{}\nfingerprint\nno-cli\nno-tls\nno-dtls\nno-multicast-peers\nno-tcp-relay\nno-software-attribute\nuser-quota=12\ntotal-quota=120\nmax-bps=1000000\nsimple-log\nlog-file=stdout\npidfile=\n",
            self.listen_ip,
            self.listen_ip,
            self.port,
            self.relay_min,
            self.relay_max,
            self.realm,
            self.realm,
            self.username,
            self.password
        );
        // Do not allow relay clients to reach infrastructure, private networks or metadata endpoints.
        for range in [
            "0.0.0.0-0.255.255.255",
            "10.0.0.0-10.255.255.255",
            "100.64.0.0-100.127.255.255",
            "127.0.0.0-127.255.255.255",
            "169.254.0.0-169.254.255.255",
            "172.16.0.0-172.31.255.255",
            "192.0.0.0-192.0.0.255",
            "192.168.0.0-192.168.255.255",
            "198.18.0.0-198.19.255.255",
            "224.0.0.0-255.255.255.255",
            "::1",
            "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            output.push_str(&format!("denied-peer-ip={range}\n"));
        }
        Ok(output)
    }
}
