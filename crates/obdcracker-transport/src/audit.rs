use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obdcracker_safety::Approved;

use crate::{Error, Response, Transport, hex};

/// Wraps a transport and appends every request, and every reply the transport returns, to a JSON
/// Lines file. Requests are logged before they are sent, so a send that crashes the program is
/// still on record. A transport may drop replies nobody read before the next request (see
/// [`crate::elm::Elm`]); those aren't logged.
#[derive(Debug)]
pub struct Audited<T> {
    inner: T,
    log: File,
    // Already escaped for a JSON string, so every line stays valid JSON whatever the link is
    // called (Windows ports such as `\\.\COM10` contain backslashes).
    link: String,
}

impl<T: Transport> Audited<T> {
    /// Opens `path` for appending. `link` names how the adapter is connected (e.g. `usb-serial`,
    /// `tcp`, `dry-run`) and is stored with every entry.
    pub fn open(path: &Path, inner: T, link: impl Into<String>) -> io::Result<Self> {
        let log = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner,
            log,
            link: json_escape(&link.into()),
        })
    }

    fn record(&mut self, dir: &str, id: u32, payload: &[u8]) -> Result<(), Error> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |t| t.as_millis());
        writeln!(
            self.log,
            r#"{{"ts_ms":{ts_ms},"dir":"{dir}","id":"{id:03X}","payload":"{}","link":"{}"}}"#,
            hex(payload),
            self.link
        )
        .map_err(|e| Error::Adapter(format!("audit log: {e}")))
    }
}

impl<T: Transport> Transport for Audited<T> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.record("tx", request.target().can_id(), request.payload())?;
        self.inner.send(request)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Response, Error> {
        let response = self.inner.recv(timeout)?;
        self.record("rx", response.source, &response.payload)?;
        Ok(response)
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
