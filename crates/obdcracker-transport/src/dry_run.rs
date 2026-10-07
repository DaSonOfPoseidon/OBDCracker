use std::io::Write;
use std::time::Duration;

use obdcracker_core::isotp::single_frame;
use obdcracker_safety::Approved;

use crate::{Error, Response, Transport, hex};

/// Writes the CAN frame each request would put on the bus, one per line, and never opens a device.
/// Every receive times out.
#[derive(Debug)]
pub struct DryRun<W> {
    out: W,
}

impl<W: Write> DryRun<W> {
    /// Writes planned frames to `out`, such as stdout or a buffer in tests.
    pub fn new(out: W) -> Self {
        Self { out }
    }

    /// Returns the writer, with everything written so far.
    pub fn into_inner(self) -> W {
        self.out
    }
}

impl<W: Write> Transport for DryRun<W> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let frame = single_frame(request.payload())
            .ok_or_else(|| Error::Adapter("multi-frame requests aren't supported yet".into()))?;
        writeln!(
            self.out,
            "{:03X} {}",
            request.target().can_id(),
            hex(frame.as_bytes())
        )
        .map_err(|e| Error::Adapter(format!("dry run output: {e}")))
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }
}
