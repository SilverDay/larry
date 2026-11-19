use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "larry", version, about = "LAMP site migration tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Discover,
    Plan,
    Preflight,
    Provision,
    Sync,
    Cutover,
    Cleanup,
}

fn main() {
    let cli = Cli::parse();
    eprintln!("not implemented yet: see docs/spec.md");
    let _ = cli.command;
    std::process::exit(1);
}
