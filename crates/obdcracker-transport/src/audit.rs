use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obdcracker_safety::Approved;

use crate::{Error, LinkEvent, Response, Transport, hex};

/// Wraps a transport and appends every request, and every reply the transport returns, to a JSON
/// Lines file. Requests are logged before they are sent, so a send that crashes the program is
/// still on record. After every call it also logs the transport's [`LinkEvent`]s: commands to
/// the adapter (`"dir":"cmd"`), reply lines nobody read before the next request
/// (`"dir":"unread"`), and how many events were lost (`"dir":"lost"`). Each line's `ts_ms` is
/// when it happened (for a reply line, when the driver read it from the link), so an event can
/// be logged after a later request. When dropped, it has the transport read what's left of the
/// last request ([`Transport::settle`]) and logs that too.
///
/// Errors from `send` and `recv` are logged too (`"dir":"err"`, with `"op"` naming the call), so
/// the log shows when an adapter misheard a request it may already have sent. A
/// [`Error::Timeout`] from `recv` isn't, since every exchange ends waiting for replies that don't
/// come.
#[derive(Debug)]
pub struct Audited<T: Transport> {
    inner: T,
    log: File,
    // Already escaped for a JSON string, so every line stays valid JSON whatever the link is
    // called (Windows ports such as `\\.\COM10` contain backslashes).
    link: String,
}

impl<T: Transport> Audited<T> {
    /// Opens `path` for appending. `link` names how the adapter is connected (e.g. `usb-serial`,
    /// `tcp`, `dry-run`) and is stored with every entry. What the transport did before, such as
    /// setting the adapter up, is logged first.
    pub fn open(path: &Path, inner: T, link: impl Into<String>) -> io::Result<Self> {
        let log = OpenOptions::new().create(true).append(true).open(path)?;
        let mut audited = Self {
            inner,
            log,
            link: json_escape(&link.into()),
        };
        audited.record_events().map_err(io::Error::other)?;
        Ok(audited)
    }

    fn record(&mut self, dir: &str, id: u32, payload: &[u8]) -> Result<(), Error> {
        let fields = format!(
            r#""dir":"{dir}","id":"{id:03X}","payload":"{}""#,
            hex(payload)
        );
        self.write(&fields)
    }

    // Logs `error` from the `op` call, then returns it. `id` is the request's CAN ID, for a send.
    fn record_error(&mut self, op: &str, id: Option<u32>, error: Error) -> Error {
        let id = id.map_or(String::new(), |id| format!(r#","id":"{id:03X}""#));
        let fields = format!(
            r#""dir":"err","op":"{op}"{id},"error":"{}""#,
            json_escape(&error.to_string())
        );
        // The adapter's error matters more than the log's.
        let _ = self.write(&fields);
        error
    }

    // Logs what the transport did besides carrying requests and replies.
    fn record_events(&mut self) -> Result<(), Error> {
        for event in self.inner.take_events() {
            match event {
                LinkEvent::Command {
                    at,
                    command,
                    answer,
                } => self.write_at(
                    at,
                    &format!(
                        r#""dir":"cmd","cmd":"{}","answer":"{}""#,
                        json_escape(&command),
                        json_escape(&answer.join(" / "))
                    ),
                )?,
                LinkEvent::Unread { at, line } => self.write_at(
                    at,
                    &format!(r#""dir":"unread","line":"{}""#, json_escape(&line)),
                )?,
                LinkEvent::Lost(count) => {
                    self.write(&format!(r#""dir":"lost","count":{count}"#))?;
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, fields: &str) -> Result<(), Error> {
        self.write_at(SystemTime::now(), fields)
    }

    fn write_at(&mut self, at: SystemTime, fields: &str) -> Result<(), Error> {
        let ts_ms = at.duration_since(UNIX_EPOCH).map_or(0, |t| t.as_millis());
        writeln!(
            self.log,
            r#"{{"ts_ms":{ts_ms},{fields},"link":"{}"}}"#,
            self.link
        )
        .map_err(|e| Error::Adapter(format!("audit log: {e}")))
    }
}

impl<T: Transport> Transport for Audited<T> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let id = request.target().can_id();
        self.record("tx", id, request.payload())?;
        let sent = self.inner.send(request);
        // What the adapter did on the way happened before any failure, which matters more than
        // the log's.
        let logged = self.record_events();
        sent.map_err(|e| self.record_error("send", Some(id), e))?;
        logged
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        let received = self.inner.recv(timeout);
        let logged = self.record_events();
        let response = match received {
            Ok(response) => response,
            Err(Error::Timeout) => return logged.and(Err(Error::Timeout)),
            Err(e) => return Err(self.record_error("recv", None, e)),
        };
        logged?;
        self.record("rx", response.source, &response.payload)?;
        Ok(response)
    }

    fn patient(&mut self, wait: Option<Duration>) -> Result<Option<Duration>, Error> {
        let result = self.inner.patient(wait);
        let logged = self.record_events();
        let waits = result.map_err(|e| self.record_error("patient", None, e))?;
        logged?;
        Ok(waits)
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        // Already logged.
        Vec::new()
    }

    fn settle(&mut self) -> Result<(), Error> {
        let settled = self.inner.settle();
        let logged = self.record_events();
        settled.map_err(|e| self.record_error("settle", None, e))?;
        logged
    }
}

impl<T: Transport> Drop for Audited<T> {
    // What's left of the last request is logged before the session ends. Nothing can report a
    // failure from here.
    fn drop(&mut self) {
        let settled = self.inner.settle();
        let _ = self.record_events();
        if let Err(e) = settled {
            self.record_error("settle", None, e);
        }
    }
}

/// Appends `events`, then `error` from the `op` call, to the audit log at `path`, as
/// [`Audited`] would have: for a transport that failed before it could be wrapped, such as an
/// adapter whose setup failed ([`crate::elm::Elm::connect_reporting`]).
///
/// # Errors
///
/// The log can't be opened or written.
pub fn log_failure(
    path: &Path,
    link: impl Into<String>,
    events: Vec<LinkEvent>,
    op: &str,
    error: &Error,
) -> io::Result<()> {
    let mut audited = Audited::open(path, Replay(events), link)?;
    let fields = format!(
        r#""dir":"err","op":"{}","error":"{}""#,
        json_escape(op),
        json_escape(&error.to_string())
    );
    audited.write(&fields).map_err(io::Error::other)
}

// Hands out the events it was given, and carries nothing.
struct Replay(Vec<LinkEvent>);

impl Transport for Replay {
    fn send(&mut self, _: &Approved) -> Result<(), Error> {
        Err(Error::Adapter("nothing to send through".to_owned()))
    }

    fn recv(&mut self, _: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }

    fn take_events(&mut self) -> Vec<LinkEvent> {
        std::mem::take(&mut self.0)
    }
}

// Escapes `s` for the inside of a JSON string (RFC 8259, section 7): quotes, backslashes and
// control characters U+0000 to U+001F.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}
