//! Explicit HTTPS hosting, or loopback HTTP behind an operator-managed HTTPS proxy.
use anyhow::{Result, bail};
use std::{future::Future, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;

/// Validated transport holding its bound listening socket.
pub struct Prepared {
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
}

impl Prepared {
    pub async fn bind(config: Config) -> Result<Self> {
        config.validate()?;
        let tls = if config.behind_proxy {
            None
        } else {
            let cert = read_pem(config.tls_cert.as_ref().unwrap(), false)?;
            let key = zeroize::Zeroizing::new(read_pem(config.tls_key.as_ref().unwrap(), true)?);
            let certs = rustls_pemfile::certs(&mut cert.as_slice())
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| anyhow::anyhow!("invalid TLS certificate PEM"))?;
            validate_certificates(&certs, &config.origin)?;
            let key = rustls_pemfile::private_key(&mut key.as_slice())
                .map_err(|_| anyhow::anyhow!("invalid TLS private key PEM"))?
                .ok_or_else(|| anyhow::anyhow!("TLS private key missing"))?;
            let mut tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls)))
        };
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            tls,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self, app: axum::Router, shutdown: impl Future<Output = ()>) -> Result<()> {
        crate::server::serve_web(self.listener, app, self.tls, shutdown).await
    }
}

/// Check deployment mistakes, not issuer trust: clients still validate their own trust chain.
/// The eMudhra exclusion inspects names in the supplied chain only; it cannot identify
/// an omitted root or determine which CA an external reverse proxy selects.
fn validate_certificates(
    certs: &[rustls::pki_types::CertificateDer<'_>],
    origin: &str,
) -> Result<()> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate chain is empty"))?;
    for der in certs {
        let (remaining, certificate) = X509Certificate::from_der(der.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid TLS X.509 certificate"))?;
        if !remaining.is_empty() {
            bail!("invalid trailing TLS certificate data");
        }
        if !certificate.validity().is_valid() {
            bail!("TLS certificate is expired or not yet valid");
        }
        for name in [certificate.subject(), certificate.issuer()] {
            if name.to_string().to_ascii_lowercase().contains("emudhra") {
                bail!("eMudhra certificates are excluded by web TLS policy");
            }
        }
    }
    let parsed = rustls::server::ParsedCertificate::try_from(leaf)
        .map_err(|_| anyhow::anyhow!("invalid TLS end-entity certificate"))?;
    let url = reqwest::Url::parse(origin)?;
    // Url brackets IPv6 hosts, while ServerName expects the unbracketed address.
    let host = url
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|_| anyhow::anyhow!("invalid TLS origin hostname"))?;
    rustls::client::verify_server_name(&parsed, &name).map_err(|_| {
        anyhow::anyhow!("TLS certificate does not match the configured origin hostname")
    })?;
    Ok(())
}

const MAX_PEM_BYTES: u64 = 1024 * 1024;

// Check the opened descriptor, not just path metadata, to avoid permission/size races.
fn read_pem(path: &std::path::Path, private: bool) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if private { libc::O_NOFOLLOW } else { 0 });
    }
    #[cfg(not(unix))]
    if private && std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("TLS private key must not be a symlink");
    }
    let file = options.open(path).map_err(|_| {
        anyhow::anyhow!("cannot open TLS PEM file (private keys must not be symlinks)")
    })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PEM_BYTES {
        bail!("TLS PEM must be a regular file no larger than 1 MiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            bail!("TLS private key must have no group or world permissions (use chmod 600)");
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        bail!("TLS PEM exceeds 1 MiB");
    }
    Ok(bytes)
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub origin: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub behind_proxy: bool,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.origin)
            .map_err(|_| anyhow::anyhow!("web origin must be a canonical HTTPS origin"))?;
        let canonical = url.origin().ascii_serialization();
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(self.origin == canonical || self.origin == format!("{canonical}/"))
        {
            bail!(
                "web origin must be a canonical HTTPS authority with no credentials, path, query or fragment"
            );
        }
        if self.behind_proxy {
            if !self.listen.ip().is_loopback() {
                bail!("proxy web listener must bind loopback only");
            }
            if self.tls_cert.is_some() || self.tls_key.is_some() {
                bail!("proxy mode does not accept a TLS certificate or key");
            }
        } else if self.tls_cert.is_none() || self.tls_key.is_none() {
            bail!("direct HTTPS requires both TLS certificate and private key");
        }
        Ok(())
    }
}
