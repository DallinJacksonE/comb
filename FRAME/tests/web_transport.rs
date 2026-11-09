use comb_frame::web_host::{Config, Prepared};

struct Fixture {
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("comb-web-tls-")
            .tempdir_in(
                std::env::var_os("TMPDIR").expect("TMPDIR required for disposable credentials"),
            )
            .unwrap();
        let fixture = Self { dir };
        fixture.openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Disposable Comb Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        fixture.openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=localhost",
        ]);
        std::fs::write(fixture.path("extensions"), "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n").unwrap();
        fixture.openssl(&[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "extensions",
        ]);
        fixture
    }
    fn openssl(&self, args: &[&str]) {
        let output = std::process::Command::new("openssl")
            .current_dir(self.dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn path(&self, file: &str) -> std::path::PathBuf {
        self.dir.path().join(file)
    }
    fn config(&self) -> Config {
        Config {
            tls_cert: Some(self.path("server.pem")),
            tls_key: Some(self.path("server.key")),
            behind_proxy: false,
            ..proxy("https://localhost")
        }
    }
    fn client(&self, trusted: bool) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(3));
        if trusted {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&std::fs::read(self.path("ca.pem")).unwrap())
                    .unwrap(),
            );
        }
        builder.build().unwrap()
    }
}

#[tokio::test]
async fn tls_requires_trusted_certificate_matching_the_requested_host_and_refuses_plaintext() {
    let fixture = Fixture::new();
    let prepared = Prepared::bind(fixture.config()).await.unwrap();
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(prepared.serve(
        axum::Router::new().route("/", axum::routing::get(|| async { "tls ok" })),
        async {
            let _ = stopped.await;
        },
    ));
    let url = format!("https://localhost:{}/", address.port());
    let response = fixture.client(true).get(&url).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "tls ok");
    assert!(fixture.client(false).get(&url).send().await.is_err());
    assert!(
        fixture
            .client(true)
            .get(format!("https://{address}/"))
            .send()
            .await
            .is_err()
    );
    assert!(
        fixture
            .client(true)
            .get(format!("http://{address}/"))
            .send()
            .await
            .is_err()
    );
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn startup_rejects_certificate_for_another_origin() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.origin = "https://wrong.example".into();
    assert!(
        Prepared::bind(config).await.is_err(),
        "accepted hostname mismatch"
    );
}

#[tokio::test]
async fn startup_rejects_expired_or_not_yet_valid_certificates() {
    for (start, end) in [
        ("20000101000000Z", "20010101000000Z"),
        ("20990101000000Z", "21000101000000Z"),
    ] {
        let fixture = Fixture::new();
        std::fs::write(fixture.path("index"), "").unwrap();
        std::fs::write(fixture.path("serial"), "01").unwrap();
        std::fs::write(fixture.path("ca.conf"), "[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n").unwrap();
        fixture.openssl(&[
            "ca",
            "-batch",
            "-notext",
            "-config",
            "ca.conf",
            "-in",
            "server.csr",
            "-out",
            "server.pem",
            "-startdate",
            start,
            "-enddate",
            end,
            "-extfile",
            "extensions",
        ]);
        assert!(
            Prepared::bind(fixture.config()).await.is_err(),
            "accepted invalid certificate validity"
        );
    }
}

#[tokio::test]
async fn startup_rejects_emudhra_subject_or_issuer_in_presented_chain() {
    let fixture = Fixture::new();
    fixture.openssl(&[
        "req",
        "-x509",
        "-key",
        "ca.key",
        "-out",
        "excluded.pem",
        "-days",
        "1",
        "-subj",
        "/CN=eMudhra Test CA/O=eMudhra",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    let mut chain = std::fs::read(fixture.path("server.pem")).unwrap();
    chain.extend(std::fs::read(fixture.path("excluded.pem")).unwrap());
    std::fs::write(fixture.path("server.pem"), chain).unwrap();
    assert!(
        Prepared::bind(fixture.config()).await.is_err(),
        "accepted excluded CA in chain"
    );
    fixture.openssl(&[
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "excluded.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "server.pem",
        "-days",
        "1",
        "-extfile",
        "extensions",
    ]);
    assert!(
        Prepared::bind(fixture.config()).await.is_err(),
        "accepted excluded issuer"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn private_key_must_be_private_regular_file_not_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    for mode in [0o644, 0o640, 0o604, 0o601, 0o660] {
        std::fs::set_permissions(
            fixture.path("server.key"),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(
            Prepared::bind(fixture.config()).await.is_err(),
            "accepted mode {mode:o}"
        );
    }
    std::fs::set_permissions(
        fixture.path("server.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink(fixture.path("server.key"), fixture.path("linked.key")).unwrap();
    let mut config = fixture.config();
    config.tls_key = Some(fixture.path("linked.key"));
    assert!(Prepared::bind(config).await.is_err());
    assert!(Prepared::bind(fixture.config()).await.is_ok());
}

#[tokio::test]
async fn pem_files_are_bounded_and_loaded_before_binding() {
    let fixture = Fixture::new();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = fixture.config();
    config.listen = occupied.local_addr().unwrap();
    std::fs::write(
        fixture.path("bad.pem"),
        b"not a certificate PRIVATE_SENTINEL",
    )
    .unwrap();
    config.tls_cert = Some(fixture.path("bad.pem"));
    let error = Prepared::bind(config)
        .await
        .err()
        .expect("invalid PEM accepted")
        .to_string();
    assert!(
        !error.contains("Address already in use"),
        "bound before checking certificate"
    );
    assert!(!error.contains("PRIVATE_SENTINEL"));
    let original_cert = std::fs::read(fixture.path("server.pem")).unwrap();
    let original_key = std::fs::read(fixture.path("server.key")).unwrap();
    for file in ["server.pem", "server.key"] {
        let mut oversized = if file == "server.pem" {
            original_cert.clone()
        } else {
            original_key.clone()
        };
        oversized.resize(1024 * 1024 + 1, b'\n');
        std::fs::write(fixture.path(file), oversized).unwrap();
        assert!(
            Prepared::bind(fixture.config()).await.is_err(),
            "accepted oversized {file}"
        );
        std::fs::write(
            fixture.path(file),
            if file == "server.pem" {
                &original_cert
            } else {
                &original_key
            },
        )
        .unwrap();
    }
    let mut config = fixture.config();
    config.tls_key = Some(fixture.path("ca.key"));
    assert!(
        Prepared::bind(config).await.is_err(),
        "accepted mismatched private key"
    );
    std::fs::write(
        fixture.path("server.key"),
        b"-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\n-----END PRIVATE KEY-----",
    )
    .unwrap();
    let error = Prepared::bind(fixture.config())
        .await
        .err()
        .expect("invalid key accepted")
        .to_string();
    assert!(!error.contains("PRIVATE_SENTINEL"));
}

#[tokio::test]
async fn proxy_serves_http_and_shutdown_releases_listener() {
    let prepared = Prepared::bind(proxy("https://example.com")).await.unwrap();
    let address = prepared.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(prepared.serve(
        axum::Router::new().route("/", axum::routing::get(|| async { "proxy ok" })),
        async {
            let _ = stopped.await;
        },
    ));
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "proxy ok");
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());
}

fn proxy(origin: &str) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        origin: origin.into(),
        tls_cert: None,
        tls_key: None,
        behind_proxy: true,
    }
}

#[test]
fn configuration_requires_canonical_https_and_explicit_secure_transport() {
    for origin in [
        "https://example.com",
        "https://example.com/",
        "https://example.com:8443",
        "https://[::1]:8443",
    ] {
        assert!(proxy(origin).validate().is_ok(), "{origin}");
    }
    for origin in [
        "http://example.com",
        "https://example.com/path",
        "https://user@example.com",
        "https://example.com?x",
        "https://example.com#x",
        "https://EXAMPLE.com",
        "https://example.com:443",
        " https://example.com",
        "https://example.com//",
        "https://example.com\\evil",
        "https://example.com/../",
    ] {
        assert!(proxy(origin).validate().is_err(), "accepted {origin}");
    }
    let mut config = proxy("https://example.com");
    config.listen = "0.0.0.0:443".parse().unwrap();
    assert!(config.validate().is_err());
    config.listen = "[::]:443".parse().unwrap();
    assert!(config.validate().is_err());
    config.listen = "[::1]:8080".parse().unwrap();
    assert!(config.validate().is_ok());
    config.tls_cert = Some("cert.pem".into());
    assert!(config.validate().is_err());
    config.behind_proxy = false;
    assert!(config.validate().is_err());
    config.tls_key = Some("key.pem".into());
    config.listen = "0.0.0.0:443".parse().unwrap();
    assert!(config.validate().is_ok());
}
