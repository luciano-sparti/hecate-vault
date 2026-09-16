use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hecate-tui",
    author = "Luciano",
    version = "0.2.0",
    about = "Interactive Terminal User Interface for Hecate Vault & Software HSM"
)]
struct Args {
    #[arg(short, long)]
    data_dir: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data_dir = if let Some(dir) = args.data_dir {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".hecate")
    };

    hecate_core::run_tui_app(&data_dir).await
}
