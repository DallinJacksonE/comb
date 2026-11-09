mod cli;
mod cli_ssh;
mod entry;
mod onboarding;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    entry::run().await
}
