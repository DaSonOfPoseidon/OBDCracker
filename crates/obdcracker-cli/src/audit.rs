use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obdcracker_safety::Approved;
use obdcracker_transport::{Error, Response, Transport};

/// Wraps a transport and appends every request and reply to a JSON Lines file. Requests are logged
/// before they are sent, so a send that crashes the tool is still on record.
#[derive(Debug)]
pub struct Audited<T> {
    inner: T,
    log: File,
    dry_run: bool,
}

impl<T: Transport> Audited<T> {
    pub fn open(path: &Path, inner: T, dry_run: bool) -> io::Result<Self> {
        let log = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner,
            log,
            dry_run,
        })
    }

    fn record(&mut self, dir: &str, id: u32, payload: &[u8]) -> Result<(), Error> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |t| t.as_millis());
        writeln!(
            self.log,
            r#"{{"ts_ms":{ts_ms},"dir":"{dir}","id":"{id:03X}","payload":"{}","dry_run":{}}}"#,
            hex(payload),
            self.dry_run
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

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
