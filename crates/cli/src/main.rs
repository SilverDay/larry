use clap::{Parser, Subcommand};
mod cleanup;
mod cutover;
mod init;
mod preflight;
mod sync;
mod target;

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
    /// Check tools, secret files, pinned host keys, database access and reachability
    Preflight,
    /// On a target, as root: pool user, pool file, Apache vhost, directories, certificates (or adopt an existing vhost)
    Provision {
        #[command(flatten)]
        t: TargetArgs,
    },
    /// On the source: push files, database dumps, certificates and manifests into the target's drop directory
    Sync {
        /// Push the files (and certificates and manifest); with --db also the database
        #[arg(long)]
        files: bool,
        /// Dump and push the database; with --files both
        #[arg(long)]
        db: bool,
        /// Let removed source files be removed from the drop directory (the sites change only through `target apply --mirror`)
        #[arg(long)]
        mirror: bool,
        #[arg(long)]
        dry_run: bool,
        /// Skip steps already done under the same sites.toml
        #[arg(long)]
        resume: bool,
        /// Only these domains
        domains: Vec<String>,
    },
    /// On the source: optional 503 freeze, final sync, then (with --check-only) check each site on the target
    Cutover {
        /// Answer 503 on the source for the moved sites before the final sync (opt-in)
        #[arg(long)]
        freeze_source: bool,
        /// Remove the maintenance page again
        #[arg(long)]
        unfreeze: bool,
        /// Only check each site on the target with curl --resolve (after `larry target apply`)
        #[arg(long)]
        check_only: bool,
        #[arg(long)]
        mirror: bool,
        #[arg(long)]
        dry_run: bool,
        domains: Vec<String>,
    },
    /// On a target, as root: remove the sshd block, lock the transfer user, archive the drop directory, check renewal
    Cleanup {
        /// Name the block was installed under (`larry target sshd --target`)
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "migrate")]
        user: String,
        #[arg(long, default_value = "/etc/ssh/sshd_config")]
        sshd_config: PathBuf,
        #[arg(long, default_value = "/srv/migration-incoming")]
        incoming: PathBuf,
        /// Do not run `certbot renew --dry-run`
        #[arg(long)]
        no_certbot: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Commands that run on a target server, as root, by an admin
    Target {
        #[command(subcommand)]
        action: TargetAction,
    },
    /// Configuration helpers
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

/// Where a target keeps things; the defaults are the spec's fixed layout.
#[derive(clap::Args, Clone)]
struct TargetArgs {
    /// Domains to handle (default: every package in the drop directory)
    domains: Vec<String>,
    #[arg(long, default_value = "/srv/migration-incoming")]
    incoming: PathBuf,
    #[arg(long, default_value = "/srv/vhosts")]
    vhost_base: PathBuf,
    #[arg(long, default_value = "www-data")]
    web_group: String,
    /// User that gets deploy ACLs on each docroot
    #[arg(long)]
    deploy_user: Option<String>,
    #[arg(long, default_value = "/var/backups/larry")]
    backup_dir: PathBuf,
    #[arg(long, default_value = "/run/lock")]
    lock_dir: PathBuf,
    /// Print exactly what would be done; change nothing
    #[arg(long)]
    dry_run: bool,
}

impl TargetArgs {
    fn common(&self) -> target::Common {
        target::Common {
            incoming: self.incoming.clone(),
            vhost_base: self.vhost_base.clone(),
            web_group: self.web_group.clone(),
            deploy_user: self.deploy_user.clone(),
            backup_dir: self.backup_dir.clone(),
            lock_dir: self.lock_dir.clone(),
            dry_run: self.dry_run,
            only: self.domains.clone(),
        }
    }
}

#[derive(Subcommand)]
enum TargetAction {
    /// Copy what arrived in the drop directory into the sites: snapshot, files, path rewriting, ownership, ACLs, database
    Apply {
        #[command(flatten)]
        t: TargetArgs,
        /// Take over files owned by another site's pool user (warn instead of refuse)
        #[arg(long)]
        adopt: bool,
        /// Remove files that are gone on the source (they move to a timestamped backup directory)
        #[arg(long)]
        mirror: bool,
        /// MySQL defaults file of the target's admin account
        #[arg(long, default_value = "/root/larry-db.cnf")]
        db_defaults_file: PathBuf,
    },
    /// Check tools, PHP-FPM versions and free space on this target
    Preflight {
        /// PHP-FPM versions the planned sites need, e.g. 8.3 (repeatable)
        #[arg(long = "php")]
        php: Vec<String>,
        #[arg(long, default_value = "/srv/vhosts")]
        vhost_base: PathBuf,
        #[arg(long, default_value = "/srv/migration-incoming")]
        incoming: PathBuf,
    },
    /// Print (or with --apply, install and verify) the sshd Match block for the transfer account
    Sshd {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "migrate")]
        user: String,
        /// The source server's public IP address
        #[arg(long)]
        source_ip: String,
        #[arg(long, default_value = "/etc/ssh/sshd_config")]
        sshd_config: PathBuf,
        /// Back up sshd_config, write the block, run sshd -t and check the effective settings
        #[arg(long)]
        apply: bool,
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
        Command::Init => {
            let deps = init::Deps {
                scan: &|a| larry_transport::ssh::scan_host_key(a),
                gen_key: &|p| {
                    larry_transport::Cmd::new("ssh-keygen")
                        .args(["-q", "-t", "ed25519", "-N", "", "-C", "larry transfer key", "-f"])
                        .arg(p)
                        .run_checked()
                        .map_err(|e| e.to_string())?;
                    std::fs::read_to_string(format!("{}.pub", p.display())).map_err(|e| e.to_string())
                },
            };
            init::run(&dir_of(&cli.config), &mut std::io::stdin().lock(), &mut std::io::stdout(), &deps)?;
            Ok(0)
        }
        Command::Preflight => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            let r = preflight::source(&cfg);
            print!("{}", r.text());
            Ok(if r.failed { 1 } else { 0 })
        }
        Command::Target { action: TargetAction::Preflight { php, vhost_base, incoming } } => {
            let r = preflight::target(php, vhost_base, incoming);
            print!("{}", r.text());
            Ok(if r.failed { 1 } else { 0 })
        }
        Command::Target { action: TargetAction::Sshd { target, user, source_ip, sshd_config, apply } } => {
            if !*apply {
                print!("{}", larry_transport::ssh::sshd_block(target, user, source_ip)?);
                println!("# printed only; add --apply to install it (backup, sshd -t and an effective-config check included)");
                return Ok(0);
            }
            let sshd = larry_transport::ssh::Sshd::find(sshd_config)?;
            let backup = larry_transport::ssh::apply_block(&sshd, target, user, source_ip, &larry_db::stamp(larry_db::now()))?;
            println!("sshd_config updated and verified (backup: {}). Reload sshd to activate it.", backup.display());
            Ok(0)
        }
        Command::Sync { files, db, mirror, dry_run, resume, domains } => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            let both = !*files && !*db;
            sync::run(
                &cfg,
                &dir_of(&cli.config),
                &sync::Opts { files: *files || both, db: *db || both, mirror: *mirror, dry_run: *dry_run, resume: *resume, only: domains.clone() },
            )
        }
        Command::Cutover { freeze_source, unfreeze, check_only, mirror, dry_run, domains } => {
            let cfg = MigrationConfig::load(&cli.config).map_err(|e| e.to_string())?;
            let o = cutover::Opts {
                freeze_source: *freeze_source,
                unfreeze: *unfreeze,
                check_only: *check_only,
                mirror: *mirror,
                dry_run: *dry_run,
                only: domains.clone(),
            };
            cutover::run(&cfg, &dir_of(&cli.config), &o, &cutover::Apache::debian())
        }
        Command::Cleanup { target, user, sshd_config, incoming, no_certbot, dry_run } => {
            target::need_root(*dry_run)?;
            cleanup::run(
                &cleanup::Opts {
                    target: target.clone(),
                    user: user.clone(),
                    sshd_config: sshd_config.clone(),
                    incoming: incoming.clone(),
                    certbot: !*no_certbot,
                    dry_run: *dry_run,
                },
                &larry_db::stamp(larry_db::now()),
            )
        }
        Command::Provision { t } => target::provision(&t.common()),
        Command::Target { action: TargetAction::Apply { t, adopt, mirror, db_defaults_file } } => {
            target::apply(&t.common(), &target::ApplyOpts { adopt: *adopt, mirror: *mirror, db_defaults_file: db_defaults_file.clone() })
        }
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
                    println!(
                        "{} was edited by hand and is left untouched.\nProposal written to {}; differences (- yours, + proposed):\n{diff}",
                        sites.display(),
                        path.display()
                    );
                    code = 2;
                }
            }
            Ok(code)
        }
    }
}
