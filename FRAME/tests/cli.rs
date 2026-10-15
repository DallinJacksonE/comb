#[test]
fn cli_exposes_management_commands_not_git_wrappers() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("serve"));
    assert!(help.contains("enroll"));
    assert!(help.contains("restore"));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .arg("push")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "comb must not expose Git wrappers"
    );
}
