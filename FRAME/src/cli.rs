//! Management command parsing. Git intentionally is not wrapped by this CLI.
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

impl Cli {
    /// Preserve the explicitly documented historical `restore -lost-frame` spelling.
    pub fn parse_compatible_from<I, T>(arguments: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString>,
    {
        let mut restore = false;
        Self::try_parse_from(arguments.into_iter().map(|argument| {
            let argument = argument.into();
            if restore && argument == "-lost-frame" {
                std::ffi::OsString::from("--lost-frame")
            } else {
                if argument == "restore" {
                    restore = true;
                }
                argument
            }
        }))
    }
}

#[derive(Parser)]
#[command(
    name = "comb",
    version,
    about = "Self-custodied FRAME and GUARD management; use git for code operations"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub data: Option<PathBuf>,
    #[arg(long, global = true, default_value = "http://127.0.0.1:7331")]
    pub api_url: String,
    #[command(subcommand)]
    pub command: Option<Command>,
}
#[derive(Subcommand)]
pub enum Command {
    /// Initialize a self-custodied identity and first FRAME.
    User {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        recovery: Option<PathBuf>,
    },
    /// Run the daemon, standard Git remote, GUI, and encrypted peer endpoint.
    Serve {
        #[arg(long, default_value = "127.0.0.1:7331")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:7332")]
        peer_listen: SocketAddr,
        #[arg(long, default_value = "FRAME/webgui/dist")]
        assets: PathBuf,
        #[arg(long, default_value_t = 0)]
        sync_seconds: u64,
    },
    /// Print the local management token (treat as a secret).
    Token,
    /// Export the public signed FRAME profile, never private keys.
    Profile {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Authorize a fresh FRAME on another device.
    Enroll {
        #[command(subcommand)]
        action: Enrollment,
    },
    /// Recover an identity and decrypt a snapshot using offline recovery material.
    Recover {
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        backup: Option<PathBuf>,
        #[arg(long)]
        owner_key: Option<String>,
    },
    /// FRAME-side repository administration, not local Git commands.
    Cell {
        #[command(subcommand)]
        action: CellCommand,
    },
    /// Manage explicit pinned peers.
    Peers {
        #[command(subcommand)]
        action: PeerCommand,
    },
    /// Generate/submit a restore credential for a revoked FRAME.
    Restore {
        #[arg(long = "lost-frame", alias = "lost_frame")]
        lost_frame: Option<PathBuf>,
        #[arg(long)]
        request_out: Option<PathBuf>,
        #[arg(long)]
        credential: Option<String>,
    },
    /// Revoke one of this identity's other FRAMEs.
    RevokeFrame { id: String },
    /// Preview unauthorized-contribution cleanup; destructive cleanup is not enabled yet.
    Clean { cell: String },
    /// Display the local management GUI URL.
    Webgui,
    /// GUARD STUN health diagnostics.
    Ice {
        #[command(subcommand)]
        action: IceCommand,
    },
}
#[derive(Subcommand)]
pub enum Enrollment {
    Request {
        #[arg(long)]
        out: PathBuf,
    },
    Authorize {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Complete {
        #[arg(long)]
        grant: PathBuf,
        #[arg(long)]
        identity_key: String,
    },
}
#[derive(Subcommand)]
pub enum CellCommand {
    List,
    Create {
        name: String,
    },
    Grant {
        id: String,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, default_value = "write")]
        role: String,
    },
    RegisterFrame {
        id: String,
        #[arg(long)]
        profile: PathBuf,
    },
    Revoke {
        id: String,
        #[arg(long)]
        identity: String,
    },
    Backup {
        id: String,
        #[arg(long)]
        out: PathBuf,
    },
    Issues {
        id: String,
    },
    Issue {
        id: String,
        title: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    Adopt {
        id: String,
        #[arg(required = true)]
        versions: Vec<String>,
    },
}
#[derive(Subcommand)]
pub enum PeerCommand {
    List,
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        key: String,
    },
    AddProfile {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        url: String,
    },
    Sync {
        id: String,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_lost_frame_flag_is_an_explicit_restore_alias() {
        let parsed =
            Cli::parse_compatible_from(["comb", "restore", "-lost-frame", "request.json"]).unwrap();
        assert!(
            matches!(parsed.command,Some(Command::Restore{lost_frame:Some(path),..}) if path==std::path::Path::new("request.json"))
        );
    }
}

#[derive(Subcommand)]
pub enum IceCommand {
    Health { address: SocketAddr },
}
