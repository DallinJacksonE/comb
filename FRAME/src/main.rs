mod cli;
mod entry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    entry::run().await
}
