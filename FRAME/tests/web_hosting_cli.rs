//! Public hosting must be explicit and must not weaken the local listener.
use std::process::{Command, Stdio};

#[test]
fn serve_help_documents_separate_secure_web_hosting() {
    let output = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["serve", "--help"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--web-listen",
        "--web-origin",
        "--tls-cert",
        "--tls-key",
        "--web-behind-proxy",
    ] {
        assert!(help.contains(flag), "missing {flag}");
    }
}

#[test]
fn unsafe_hosting_configuration_fails_before_initialization_or_unlock() {
    let directory = tempfile::tempdir().unwrap();
    let cases: &[(&[&str], &str)] = &[
        (&["--web-listen", "127.0.0.1:7443"], "web-origin"),
        (&["--web-origin", "https://code.example.test"], "web-listen"),
        (
            &[
                "--web-listen",
                "127.0.0.1:7443",
                "--web-origin",
                "http://code.example.test",
                "--web-behind-proxy",
            ],
            "HTTPS",
        ),
        (
            &[
                "--web-listen",
                "0.0.0.0:7443",
                "--web-origin",
                "https://code.example.test",
                "--web-behind-proxy",
            ],
            "loopback",
        ),
        (
            &[
                "--web-listen",
                "127.0.0.1:7443",
                "--web-origin",
                "https://code.example.test",
            ],
            "cert",
        ),
    ];
    for (index, (options, message)) in cases.iter().enumerate() {
        let data = directory.path().join(format!("frame-{index}"));
        let output = Command::new(env!("CARGO_BIN_EXE_comb"))
            .args(["--data", data.to_str().unwrap(), "serve", "--managed"])
            .args(*options)
            .env_remove("COMB_PASSWORD")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .to_lowercase()
                .contains(&message.to_lowercase()),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !data.exists(),
            "invalid hosting options must fail before local state is created"
        );
    }
}
