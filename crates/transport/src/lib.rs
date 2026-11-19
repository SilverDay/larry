//! larry-transport: safe wrapper for calling external tools (ssh, rsync, mysqldump, ...).
//!
//! Every call goes through `std::process::Command` with an argument list, never
//! a shell string. stdin is always explicit: `/dev/null` unless data is piped,
//! which removes the "ssh swallows the rest of the loop's stdin" class of bug.
//! Secrets must never be passed as arguments; use defaults files.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
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
    fn display_quotes_for_reading() {
        assert_eq!(Cmd::new("rsync").args(["-a", "a b", "it's"]).display(), "rsync -a 'a b' 'it'\\''s'");
    }
}
