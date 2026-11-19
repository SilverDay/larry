use clap::{Parser, Subcommand};
use larry_config::MigrationConfig;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "larry", version, about = "LAMP site migration tool")]
struct Cli {
    /// Path to migration.toml (inventory.jsonl and sites.toml live next to it)
    #[arg(short, long, global = true, default_value = "migration.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wizard: targets, host-key pinning, migration.toml, SSH config
    Init,
    /// Read-only source discovery: writes inventory.jsonl and prints a report
    Discover {
        /// Do not run SHOW DATABASES; detected names stay unverified and are flagged
        #[arg(long)]
        no_db_check: bool,
        /// How deep to look for config files below each vhost directory
        #[arg(long, default_value_t = 5)]
        max_depth: usize,
    },
    /// Write sites.toml from the inventory (an edited sites.toml is never overwritten)
    Plan {
        /// Decide a database by hand: DOMAIN=NAME, or DOMAIN= for "no database"
        #[arg(long = "db", value_name = "DOMAIN=NAME")]
        db: Vec<String>,
    },
    Preflight,
    Provision,
    Sync,
    Cutover,
    Cleanup,
    /// Configuration helpers
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Parse migration.toml and refuse group- or world-readable secret files
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("larry: {e}");
            ExitCode::from(1)
        }
    }
}

fn dir_of(config: &Path) -> PathBuf {
    match config.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn run(cli: &Cli) -> Result<u8, String> {
    match &cli.command {
        Command::Config { action: ConfigAction::Check } => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            cfg.check_secret_files().map_err(|e| e.to_string())?;
            println!("{}: ok ({} target(s))", cli.config.display(), cfg.targets.len());
            Ok(0)
        }
        Command::Discover { no_db_check, max_depth } => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            let defaults = Path::new(&cfg.source.db_defaults_file);
            if !no_db_check {
                cfg.check_secret_files().map_err(|e| e.to_string())?;
            }
            let env = larry_discover::Env::collect((!no_db_check).then_some(defaults))?;
            let opts = larry_discover::Options { vhost_base: cfg.layout.vhost_base.clone(), max_depth: *max_depth };
            let records = larry_discover::build_inventory(&env, &opts);
            let out = dir_of(&cli.config).join("inventory.jsonl");
            larry_discover::write_inventory(&out, &records)?;
            print!("{}", larry_discover::report(&records));
            println!("\nwrote {} record(s) to {}", records.len(), out.display());
            Ok(larry_discover::exit_code(&records) as u8)
        }
        Command::Plan { db } => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            let dir = dir_of(&cli.config);
            let records = larry_discover::read_inventory(&dir.join("inventory.jsonl"))?;
            let mut answers = larry_plan::Answers::new();
            for a in db {
                let (d, n) = a.split_once('=').ok_or_else(|| format!("--db expects DOMAIN=NAME, got '{a}'"))?;
                answers.insert(d.trim().into(), (!n.trim().is_empty()).then(|| n.trim().to_string()));
            }
            let plan = larry_plan::build(&records, &cfg, &answers)?;
            let sites = dir.join("sites.toml");
            let written = larry_plan::write_plan(&sites, &plan)?;
            print!("{}", larry_plan::summary(&plan));
            let mut code = if plan.held_back.is_empty() { 0 } else { 2 };
            match written {
                larry_plan::Written::Created(p) => println!("wrote {}", p.display()),
                larry_plan::Written::Updated(p) => println!("updated {} (it had not been edited)", p.display()),
                larry_plan::Written::Unchanged(p) => println!("{} is up to date", p.display()),
                larry_plan::Written::Diverted { path, diff } => {
                    println!("{} was edited by hand and is left untouched.\nProposal written to {}; differences (- yours, + proposed):\n{diff}", sites.display(), path.display());
                    code = 2;
                }
            }
            Ok(code)
        }
        _ => Err("not implemented yet: see docs/spec.md".into()),
    }
}
