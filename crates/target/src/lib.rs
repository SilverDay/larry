//! larry-target: what `provision` and `target apply` do on a target server.
//!
//! Everything here is split into a pure part (render a pool file, plan ownership, rewrite paths,
//! validate what came from the drop directory) and a small executor. The plan is a list of
//! [`steps::Step`]s, so `--dry-run` prints exactly what a real run would do.

pub mod manifest;
pub mod perms;
pub mod pool;
pub mod provision;
pub mod appconfig;
pub mod apply;
pub mod rewrite;
pub mod steps;
pub mod tls;
pub mod vhost;

pub use manifest::Manifest;
