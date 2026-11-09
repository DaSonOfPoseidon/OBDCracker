//! Fetching a URL with curl, or with wget where curl isn't installed. Neither is a dependency of
//! this crate: Windows 10 and later ship `curl.exe`, and the install scripts need one of the two.
//! See docs/install.md#updating.

use std::ffi::OsString;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Which representation of a GitHub reply to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accept {
    Json,
    /// The bare commit hash a ref names.
    Sha,
    Plain,
}

impl Accept {
    fn header(self) -> Option<&'static str> {
        match self {
            Accept::Json => Some("Accept: application/vnd.github+json"),
            Accept::Sha => Some("Accept: application/vnd.github.sha"),
            Accept::Plain => None,
        }
    }
}

/// A server's answer. Every status comes back, so the caller says which ones it accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// An HTTPS GET whose reply is at most `limit` bytes long and takes a bounded time.
pub(crate) trait Http {
    fn get(&self, url: &str, accept: Accept, limit: usize) -> Result<Reply, String>;
}

// The most of a failing program's complaint that is kept: enough for its message.
const STDERR_KEPT: u64 = 64 * 1024;
// What the program may take in all, however its own timeouts add up.
const DEADLINE: Duration = Duration::from_secs(120);
// What curl's `-w` adds after the body: a newline and the status's three digits.
const CURL_TRAILER: usize = 8;

/// A program to run, with the arguments that go before the ones for the request.
#[derive(Debug, Clone)]
pub(crate) struct Tool {
    program: OsString,
    prefix: Vec<OsString>,
}

impl Tool {
    pub(crate) fn new(program: &str) -> Self {
        Tool {
            program: program.into(),
            prefix: Vec::new(),
        }
    }

    fn command(&self, args: Vec<OsString>) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.prefix).args(args);
        command
    }

    fn name(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }
}

/// [`Http`] through the `curl` or `wget` on the path.
#[derive(Debug, Clone)]
pub(crate) struct SystemHttp {
    curl: Tool,
    wget: Tool,
    deadline: Duration,
}

impl SystemHttp {
    pub(crate) fn new() -> Self {
        SystemHttp {
            curl: Tool::new("curl"),
            wget: Tool::new("wget"),
            deadline: DEADLINE,
        }
    }
}

impl Http for SystemHttp {
    fn get(&self, url: &str, accept: Accept, limit: usize) -> Result<Reply, String> {
        let curl = capture(
            self.curl.command(curl_args(url, accept)),
            limit + CURL_TRAILER,
            self.deadline,
        );
        match curl {
            Ok(done) => return curl_reply(&done, limit),
            // Only a missing curl falls back: one that ran and failed would fail the same way
            Err(RunError::Failed(why)) => return Err(why),
            Err(RunError::Missing) => {}
        }
        match capture(
            self.wget.command(wget_args(url, accept)),
            limit,
            self.deadline,
        ) {
            Ok(done) => wget_reply(&done),
            Err(RunError::Failed(why)) => Err(why),
            Err(RunError::Missing) => Err(format!(
                "need curl or wget to reach GitHub, and neither is installed ({} and {} not found)",
                self.curl.name(),
                self.wget.name()
            )),
        }
    }
}

fn curl_args(url: &str, accept: Accept) -> Vec<OsString> {
    // `-q` first, so a .curlrc can't change what is asked. The status comes after the body, because
    // without `-f` every status has a body and the caller needs the 404.
    let mut args: Vec<OsString> = [
        "-q",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "-sS",
        "-L",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "15",
        "--max-time",
        "100",
        "-w",
        "\n%{http_code}",
    ]
    .map(Into::into)
    .to_vec();
    if let Some(header) = accept.header() {
        args.extend(["-H".into(), header.into()]);
    }
    args.push(url.into());
    args
}

fn wget_args(url: &str, accept: Accept) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--https-only",
        "--no-verbose",
        "-S",
        "--tries=1",
        "--timeout=30",
        "--max-redirect=5",
        "-O",
        "-",
    ]
    .map(Into::into)
    .to_vec();
    if let Some(header) = accept.header() {
        args.push(format!("--header={header}").into());
    }
    args.push(url.into());
    args
}

fn curl_reply(done: &Captured, limit: usize) -> Result<Reply, String> {
    if done.code != Some(0) {
        return Err(format!(
            "curl failed ({}): {}",
            done.code.map_or("killed".to_owned(), |c| c.to_string()),
            printable(&done.stderr)
        ));
    }
    let cut = done
        .stdout
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or("curl's output has no status")?;
    let (body, status) = (&done.stdout[..cut], &done.stdout[cut + 1..]);
    let status = std::str::from_utf8(status)
        .ok()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..600).contains(s))
        .ok_or("curl's output ends with no HTTP status")?;
    if body.len() > limit {
        return Err(too_large(limit));
    }
    Ok(Reply {
        status,
        body: body.to_vec(),
    })
}

fn wget_reply(done: &Captured) -> Result<Reply, String> {
    let Some(status) = wget_status(&done.stderr) else {
        return Err(format!(
            "wget failed ({}): {}",
            done.code.map_or("killed".to_owned(), |c| c.to_string()),
            printable(&done.stderr)
        ));
    };
    if (200..300).contains(&status) {
        if done.code != Some(0) {
            return Err(format!("wget failed after HTTP {status}"));
        }
        return Ok(Reply {
            status,
            body: done.stdout.clone(),
        });
    }
    // wget keeps no body for an error status
    Ok(Reply {
        status,
        body: Vec::new(),
    })
}

// The last status `-S` printed, which is the final answer after any redirects.
fn wget_status(stderr: &[u8]) -> Option<u16> {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("HTTP/")?;
            rest.split_whitespace().nth(1)?.parse::<u16>().ok()
        })
        .next_back()
}

fn too_large(limit: usize) -> String {
    format!("the reply is longer than the {limit} bytes expected")
}

// A program's message reaches the terminal, so only plain characters pass.
fn printable(text: &[u8]) -> String {
    String::from_utf8_lossy(text)
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { ' ' })
        .take(200)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug)]
struct Captured {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum RunError {
    Missing,
    Failed(String),
}

// Runs a program with nothing on its input and collects its output: at most `limit` bytes of it,
// and at most `deadline` of time. Past either, the program is killed and the run fails.
fn capture(mut command: Command, limit: usize, deadline: Duration) -> Result<Captured, RunError> {
    let name = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            RunError::Missing
        } else {
            RunError::Failed(format!("couldn't start {name}: {e}"))
        }
    })?;
    let (Some(stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(RunError::Failed(format!("couldn't read {name}'s output")));
    };
    let end = Instant::now() + deadline;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut body = Vec::new();
        // One byte more than the limit says the reply is too long, without keeping the rest
        let read = stdout.take(limit as u64 + 1).read_to_end(&mut body);
        let _ = sender.send(read.map(|_| body));
    });
    let errors = thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = (&mut stderr).take(STDERR_KEPT).read_to_end(&mut kept);
        let _ = io::copy(&mut stderr, &mut io::sink());
        kept
    });
    let result = match receiver.recv_timeout(deadline) {
        Ok(Ok(body)) if body.len() > limit => Err(too_large(limit)),
        Ok(Ok(body)) => wait_until(&mut child, end).map(|code| (code, body)),
        Ok(Err(e)) => Err(format!("couldn't read {name}'s output: {e}")),
        Err(_) => Err(format!(
            "{name} took longer than {} seconds",
            deadline.as_secs()
        )),
    };
    match result {
        Ok((code, stdout)) => Ok(Captured {
            code,
            stdout,
            stderr: errors.join().unwrap_or_default(),
        }),
        Err(why) => {
            // The readers end when the pipes close; a program's own children may keep them
            // open, so they aren't waited for.
            let _ = child.kill();
            let _ = child.wait();
            Err(RunError::Failed(why))
        }
    }
}

fn wait_until(child: &mut std::process::Child, end: Instant) -> Result<Option<i32>, String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code()),
            Ok(None) if Instant::now() >= end => return Err("it didn't exit in time".to_owned()),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("couldn't wait for it: {e}")),
        }
    }
}

#[cfg(test)]
pub(super) mod fake {
    use std::cell::RefCell;

    use super::{Accept, Http, Reply, too_large};

    /// Answers each URL with a canned reply and remembers what was asked.
    pub(in crate::update) struct FakeHttp {
        replies: Vec<(String, Result<Reply, String>)>,
        asked: RefCell<Vec<(String, Accept)>>,
    }

    impl FakeHttp {
        pub(in crate::update) fn new() -> Self {
            FakeHttp {
                replies: Vec::new(),
                asked: RefCell::new(Vec::new()),
            }
        }

        pub(in crate::update) fn reply(mut self, url: &str, status: u16, body: &[u8]) -> Self {
            let reply = Reply {
                status,
                body: body.to_vec(),
            };
            self.replies.push((url.to_owned(), Ok(reply)));
            self
        }

        pub(in crate::update) fn fails(mut self, url: &str, why: &str) -> Self {
            self.replies.push((url.to_owned(), Err(why.to_owned())));
            self
        }

        pub(in crate::update) fn urls(&self) -> Vec<String> {
            self.asked
                .borrow()
                .iter()
                .map(|(url, _)| url.clone())
                .collect()
        }

        pub(in crate::update) fn accepts(&self) -> Vec<Accept> {
            self.asked
                .borrow()
                .iter()
                .map(|(_, accept)| *accept)
                .collect()
        }
    }

    impl Http for FakeHttp {
        fn get(&self, url: &str, accept: Accept, limit: usize) -> Result<Reply, String> {
            self.asked.borrow_mut().push((url.to_owned(), accept));
            let (_, reply) = self
                .replies
                .iter()
                .find(|(known, _)| known == url)
                .ok_or_else(|| format!("unexpected request for {url}"))?;
            match reply {
                Ok(reply) if reply.body.len() > limit => Err(too_large(limit)),
                other => other.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(args: &[OsString]) -> Vec<&str> {
        args.iter().map(|a| a.to_str().unwrap()).collect()
    }

    #[test]
    fn curl_is_told_to_ignore_its_config_and_to_speak_only_https() {
        let args = curl_args("https://example.test/x", Accept::Json);
        let args = text(&args);
        assert_eq!(args[0], "-q");
        for pair in [
            ["--proto", "=https"],
            ["--proto-redir", "=https"],
            ["--max-redirs", "5"],
            ["-H", "Accept: application/vnd.github+json"],
        ] {
            assert!(args.windows(2).any(|w| w == pair), "{pair:?} in {args:?}");
        }
        assert!(args.contains(&"--tlsv1.2"));
        assert!(args.contains(&"--connect-timeout") && args.contains(&"--max-time"));
        assert!(
            !args.contains(&"-f"),
            "the status is read, not turned into an exit code"
        );
        assert_eq!(args.last(), Some(&"https://example.test/x"));
    }

    #[test]
    fn each_kind_of_reply_asks_for_its_own_media_type() {
        let sha = curl_args("https://example.test/x", Accept::Sha);
        assert!(text(&sha).contains(&"Accept: application/vnd.github.sha"));
        let plain = curl_args("https://example.test/x", Accept::Plain);
        assert!(!text(&plain).contains(&"-H"));
        let wget = wget_args("https://example.test/x", Accept::Sha);
        assert!(text(&wget).contains(&"--header=Accept: application/vnd.github.sha"));
        assert!(
            !text(&wget_args("https://example.test/x", Accept::Plain))
                .iter()
                .any(|a| a.starts_with("--header"))
        );
    }

    #[test]
    fn wget_is_held_to_https_and_asked_for_the_status() {
        let args = wget_args("https://example.test/x", Accept::Json);
        let args = text(&args);
        assert!(args.contains(&"--https-only"));
        assert!(args.contains(&"-S"));
        assert!(args.windows(2).any(|w| w == ["-O", "-"]));
        assert_eq!(args.last(), Some(&"https://example.test/x"));
    }

    fn done(code: i32, stdout: &str, stderr: &str) -> Captured {
        Captured {
            code: Some(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn curl_s_status_follows_the_body() {
        for (out, status, body) in [
            ("{}\n200", 200, "{}"),
            ("\n404", 404, ""),
            ("a\nb\n\n200", 200, "a\nb\n"),
            ("x\n403", 403, "x"),
        ] {
            let reply = curl_reply(&done(0, out, ""), 100).unwrap();
            assert_eq!(
                (reply.status, reply.body),
                (status, body.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn a_curl_reply_without_a_readable_status_is_an_error() {
        for out in [
            "",
            "200",
            "body\n",
            "body\n20",
            "body\n2000",
            "body\n+20",
            "body\n 20",
            "body\n000",
            "body\n999",
            "body\nabc",
        ] {
            assert!(curl_reply(&done(0, out, ""), 100).is_err(), "{out:?}");
        }
    }

    #[test]
    fn a_failed_curl_says_why_and_a_long_body_is_refused() {
        let err =
            curl_reply(&done(6, "\n000", "curl: (6) Could not resolve host"), 100).unwrap_err();
        assert!(
            err.contains("(6)") && err.contains("Could not resolve host"),
            "{err}"
        );
        assert!(curl_reply(&done(0, &format!("{}\n200", "a".repeat(101)), ""), 100).is_err());
        assert!(curl_reply(&done(0, &format!("{}\n200", "a".repeat(100)), ""), 100).is_ok());
        let killed = Captured {
            code: None,
            stdout: vec![],
            stderr: vec![],
        };
        assert!(curl_reply(&killed, 100).unwrap_err().contains("killed"));
    }

    #[test]
    fn wget_s_last_status_is_the_answer() {
        let stderr = "--2026-11-09 12:00:00--  https://x.test/\n  HTTP/1.1 301 Moved Permanently\n  Location: https://y.test/\n  HTTP/2 200 \n";
        assert_eq!(wget_status(stderr.as_bytes()), Some(200));
        assert_eq!(wget_status(b"  HTTP/1.1 404 Not Found\n"), Some(404));
        for none in [
            "",
            "wget: unable to resolve host address\n",
            "  HTTP/1.1 abc\n",
            "HTTP/1.1\n",
        ] {
            assert_eq!(wget_status(none.as_bytes()), None, "{none:?}");
        }
    }

    #[test]
    fn wget_replies_follow_the_status() {
        let ok = wget_reply(&done(0, "[]", "  HTTP/1.1 200 OK\n")).unwrap();
        assert_eq!((ok.status, ok.body), (200, b"[]".to_vec()));
        let missing = wget_reply(&done(8, "", "  HTTP/1.1 404 Not Found\n")).unwrap();
        assert_eq!((missing.status, missing.body), (404, vec![]));
        // An error exit after an OK status is not a complete body
        assert!(wget_reply(&done(4, "[", "  HTTP/1.1 200 OK\n")).is_err());
        assert!(wget_reply(&done(4, "", "wget: unable to resolve host address 'x'\n")).is_err());
    }

    #[test]
    fn what_a_program_prints_is_made_safe_for_a_terminal() {
        let nasty = "curl: (6) bad\x1b[31m red\x1b]0;title\x07 \u{202e}end\r\nsecond\tline";
        let shown = printable(nasty.as_bytes());
        assert!(
            shown.bytes().all(|b| b == b' ' || b.is_ascii_graphic()),
            "{shown:?}"
        );
        assert!(!shown.contains('\x1b'));
        assert!(printable("a".repeat(1000).as_bytes()).len() <= 200);
        assert_eq!(printable(b""), "");
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Tool {
        Tool {
            program: "sh".into(),
            prefix: vec!["-c".into(), script.into(), "fake".into()],
        }
    }

    #[cfg(unix)]
    fn missing() -> Tool {
        Tool::new("/nonexistent/obdcracker-test/tool")
    }

    #[cfg(unix)]
    fn http(curl: Tool, wget: Tool) -> SystemHttp {
        SystemHttp {
            curl,
            wget,
            deadline: Duration::from_secs(20),
        }
    }

    #[cfg(unix)]
    #[test]
    fn curl_gets_the_request_and_its_status() {
        // The fake prints the arguments it got as the body
        let tool = sh(r#"printf '%s|' "$@"; printf '\n200'"#);
        let reply = http(tool, missing())
            .get("https://example.test/a", Accept::Sha, 4096)
            .unwrap();
        assert_eq!(reply.status, 200);
        let body = String::from_utf8(reply.body).unwrap();
        assert!(body.starts_with("-q|"), "{body}");
        assert!(
            body.contains("|Accept: application/vnd.github.sha|"),
            "{body}"
        );
        assert!(body.ends_with("|https://example.test/a|"), "{body}");
    }

    #[cfg(unix)]
    #[test]
    fn wget_is_used_only_when_curl_is_missing() {
        let wget = sh(r"printf '[]'; echo '  HTTP/1.1 200 OK' >&2");
        let reply = http(missing(), wget)
            .get("https://example.test/a", Accept::Json, 4096)
            .unwrap();
        assert_eq!((reply.status, reply.body), (200, b"[]".to_vec()));

        let wget = sh(r"echo '  HTTP/1.1 404 Not Found' >&2; exit 8");
        let reply = http(missing(), wget)
            .get("https://example.test/a", Accept::Json, 4096)
            .unwrap();
        assert_eq!(reply.status, 404);
    }

    #[cfg(unix)]
    #[test]
    fn a_curl_that_ran_and_failed_is_not_retried_with_wget() {
        let curl = sh(r"echo 'curl: (28) timed out' >&2; exit 28");
        let wget = sh(r"printf '[]'; echo '  HTTP/1.1 200 OK' >&2");
        let err = http(curl, wget)
            .get("https://example.test/a", Accept::Json, 4096)
            .unwrap_err();
        assert!(err.contains("(28)"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn neither_tool_installed_says_what_to_install() {
        let err = http(missing(), missing())
            .get("https://example.test/a", Accept::Json, 4096)
            .unwrap_err();
        assert!(err.contains("curl or wget"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_reply_that_never_stops_is_cut_off_at_the_limit() {
        let curl = sh("yes");
        let err = http(curl, missing())
            .get("https://example.test/a", Accept::Json, 1000)
            .unwrap_err();
        assert!(err.contains("longer than"), "{err}");
        let wget = sh("yes; echo '  HTTP/1.1 200 OK' >&2");
        let err = http(missing(), wget)
            .get("https://example.test/a", Accept::Json, 1000)
            .unwrap_err();
        assert!(err.contains("longer than"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_reply_exactly_at_the_limit_is_accepted() {
        let curl = sh(r"head -c 1000 /dev/zero | tr '\0' a; printf '\n200'");
        let reply = http(curl, missing())
            .get("https://example.test/a", Accept::Json, 1000)
            .unwrap();
        assert_eq!(reply.body.len(), 1000);
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_never_answers_is_killed_at_the_deadline() {
        let start = Instant::now();
        let slow = SystemHttp {
            curl: sh("sleep 30"),
            wget: missing(),
            deadline: Duration::from_millis(300),
        };
        let err = slow
            .get("https://example.test/a", Accept::Json, 1000)
            .unwrap_err();
        assert!(err.contains("took longer"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_closes_its_output_and_hangs_is_killed_at_the_deadline() {
        let slow = SystemHttp {
            curl: sh("exec 1>&-; sleep 30"),
            wget: missing(),
            deadline: Duration::from_millis(300),
        };
        let start = Instant::now();
        assert!(
            slow.get("https://example.test/a", Accept::Json, 1000)
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}
