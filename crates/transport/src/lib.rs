//! larry-transport: safe wrapper for calling external tools (ssh, rsync, mysqldump, ...).
//!
//! Every call goes through `std::process::Command` with an argument list, never
//! a shell string. stdin is always explicit: `/dev/null` unless data is piped,
//! which removes the "ssh swallows the rest of the loop's stdin" class of bug.
//! Secrets must never be passed as arguments; use defaults files.

pub mod ssh;
pub mod transfer;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[derive(Debug)]
pub enum CmdError {
    Spawn { program: String, source: std::io::Error },
    Failed { program: String, code: Option<i32>, stderr: String },
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CmdError::Spawn { program, source } => write!(f, "cannot run {program}: {source}"),
            CmdError::Failed { program, code, stderr } => match code {
                Some(c) => write!(f, "{program} exited with status {c}: {}", stderr.trim_end()),
                None => write!(f, "{program} was killed by a signal: {}", stderr.trim_end()),
            },
        }
    }
}
impl std::error::Error for CmdError {}

#[derive(Debug, Clone)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

#[derive(Debug, Clone)]
enum Stdin {
    Null,
    Data(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Cmd {
    program: OsString,
    args: Vec<OsString>,
    stdin: Stdin,
}

impl Cmd {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Cmd { program: program.as_ref().to_owned(), args: Vec::new(), stdin: Stdin::Null }
    }

    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Self {
        self.args.push(a.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(it.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Pipe these bytes to the child's stdin (default is /dev/null).
    pub fn stdin_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Stdin::Data(data.into());
        self
    }

    /// The exact command, for `--dry-run` output and logs. Quoted for readability only; never executed.
    pub fn display(&self) -> String {
        let mut parts = vec![quote(&self.program.to_string_lossy())];
        parts.extend(self.args.iter().map(|a| quote(&a.to_string_lossy())));
        parts.join(" ")
    }

    /// Run and return the output whatever the exit status.
    pub fn run(&self) -> Result<Output, CmdError> {
        let program = self.program.to_string_lossy().into_owned();
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(match self.stdin {
                Stdin::Null => Stdio::null(),
                Stdin::Data(_) => Stdio::piped(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| CmdError::Spawn { program: program.clone(), source })?;

        // Feed stdin from a thread so a child that fills its output pipe cannot deadlock us.
        let writer = if let Stdin::Data(data) = &self.stdin {
            let mut stdin = child.stdin.take().expect("piped stdin");
            let data = data.clone();
            Some(std::thread::spawn(move || {
                // A child that exits early closes the pipe; that is not our error.
                let _ = stdin.write_all(&data);
            }))
        } else {
            None
        };

        let out = child
            .wait_with_output()
            .map_err(|source| CmdError::Spawn { program: program.clone(), source })?;
        if let Some(w) = writer {
            let _ = w.join();
        }
        Ok(Output {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Run with data streamed through: `input` (if any) is copied to the child's stdin and the
    /// child's stdout (if `output` is given) is copied to `output`, without holding it in memory.
    /// Used for dumps (`mysqldump` to a gzip file) and imports (a gzip file into `mysql`).
    /// stderr is captured; the returned `stdout` is empty when `output` is given.
    pub fn stream(
        &self,
        input: Option<&mut (dyn Read + Send)>,
        output: Option<&mut (dyn Write + Send)>,
    ) -> Result<Output, CmdError> {
        let program = self.program.to_string_lossy().into_owned();
        let spawn_err = |source| CmdError::Spawn { program: program.clone(), source };
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(if input.is_some() || matches!(self.stdin, Stdin::Data(_)) { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_err)?;
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let data = match &self.stdin {
            Stdin::Data(d) => Some(d.clone()),
            Stdin::Null => None,
        };
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let mut copy_err: Option<std::io::Error> = None;
        std::thread::scope(|sc| {
            let err_t = sc.spawn(|| {
                let _ = stderr.read_to_end(&mut err_buf);
            });
            let out_t = sc.spawn(|| match output {
                Some(w) => std::io::copy(&mut stdout, w).err(),
                None => {
                    let _ = stdout.read_to_end(&mut out_buf);
                    None
                }
            });
            // A child that exits early closes the pipe; that is reported through its status.
            if let Some(mut w) = stdin.take() {
                if let Some(r) = input {
                    let _ = std::io::copy(r, &mut w);
                } else if let Some(d) = &data {
                    let _ = w.write_all(d);
                }
            }
            copy_err = out_t.join().ok().flatten();
            let _ = err_t.join();
        });
        let status = child.wait().map_err(spawn_err)?;
        if let Some(e) = copy_err {
            return Err(CmdError::Spawn { program, source: e });
        }
        Ok(Output {
            code: status.code(),
            stdout: String::from_utf8_lossy(&out_buf).into_owned(),
            stderr: String::from_utf8_lossy(&err_buf).into_owned(),
        })
    }

    /// Run and fail on any non-zero exit.
    pub fn run_checked(&self) -> Result<Output, CmdError> {
        let out = self.run()?;
        if out.success() {
            Ok(out)
        } else {
            Err(CmdError::Failed {
                program: self.program.to_string_lossy().into_owned(),
                code: out.code,
                stderr: out.stderr,
            })
        }
    }
}

/// First of `names` found in PATH (e.g. `mysqldump` or `mariadb-dump`).
pub fn find_tool(names: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for n in names {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(n);
            if p.is_file() {
                return Some((*n).to_string());
            }
        }
    }
    None
}

/// A private working directory: created 0700 if missing, refused if it is a symlink or
/// not owned by the caller (staging dirs usually live in a shared place such as /var/tmp).
pub fn ensure_private_dir(dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let d = dir.display();
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => return Err(format!("{d} is a symlink: refusing")),
        Ok(m) if !m.is_dir() => return Err(format!("{d} is not a directory")),
        Ok(m) => {
            // /proc/self is owned by the user the process runs as.
            let me = std::fs::metadata("/proc/self").map(|x| x.uid());
            if me.map_err(|e| e.to_string())? != m.uid() {
                return Err(format!("{d} is not owned by you: refusing"));
            }
        }
        Err(_) => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("{d}: {e}"))?,
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{d}: {e}"))
}

fn quote(s: &str) -> String {
    let plain = !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_never_interpreted_by_a_shell() {
        let out = Cmd::new("echo").arg("; echo hacked $(id) `id`").run_checked().unwrap();
        assert_eq!(out.stdout, "; echo hacked $(id) `id`\n");
    }

    #[test]
    fn stdin_is_null_by_default() {
        // `cat` would block forever if it inherited our stdin.
        let out = Cmd::new("cat").run_checked().unwrap();
        assert_eq!(out.stdout, "");
    }

    #[test]
    fn stdin_data_is_piped_even_when_large() {
        let data = vec![b'x'; 1_000_000];
        let out = Cmd::new("cat").stdin_data(data.clone()).run_checked().unwrap();
        assert_eq!(out.stdout.len(), data.len());
    }

    #[test]
    fn failures_carry_status_and_stderr() {
        let err = Cmd::new("sh").args(["-c", "echo boom >&2; exit 3"]).run_checked().unwrap_err();
        match err {
            CmdError::Failed { code, stderr, .. } => {
                assert_eq!(code, Some(3));
                assert_eq!(stderr.trim(), "boom");
            }
            e => panic!("unexpected {e}"),
        }
        assert!(matches!(Cmd::new("no-such-tool-xyz").run(), Err(CmdError::Spawn { .. })));
    }

    #[test]
    fn streaming_copies_both_ways_without_buffering_in_the_result() {
        let mut input: &[u8] = &vec![b'y'; 2_000_000];
        let mut out: Vec<u8> = Vec::new();
        let r = Cmd::new("cat").stream(Some(&mut input), Some(&mut out)).unwrap();
        assert_eq!(r.code, Some(0));
        assert_eq!(out.len(), 2_000_000);
        assert!(r.stdout.is_empty());
        let mut out2: Vec<u8> = Vec::new();
        let r = Cmd::new("sh").args(["-c", "echo data; echo oops >&2; exit 4"]).stream(None, Some(&mut out2)).unwrap();
        assert_eq!((r.code, out2.as_slice(), r.stderr.trim()), (Some(4), &b"data\n"[..], "oops"));
    }

    #[test]
    fn private_dir_rules() {
        let base = std::env::temp_dir().join(format!("larry-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let d = base.join("stage");
        ensure_private_dir(&d).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        let link = base.join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        assert!(find_tool(&["no-such-tool-xyz", "sh"]).as_deref() == Some("sh"));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn display_quotes_for_reading() {
        assert_eq!(Cmd::new("rsync").args(["-a", "a b", "it's"]).display(), "rsync -a 'a b' 'it'\\''s'");
    }
}
