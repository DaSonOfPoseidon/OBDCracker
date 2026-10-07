use std::io::Write;
use std::time::Duration;

use obdcracker_core::isotp::{Addressing, FlowControl, FlowStatus, Segmenter, Step};
use obdcracker_safety::Approved;

use crate::{Error, Response, Transport, hex};

const ASSUMED_FLOW_CONTROL: FlowControl = FlowControl {
    status: FlowStatus::ContinueToSend,
    block_size: 0,
    st_min: Duration::ZERO,
};

/// Writes the CAN frames each request would put on the bus, one per line, and never opens a device.
/// A multi-frame request is printed as if the ECU answered with continue-to-send and no block
/// limit. Every receive times out.
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
        let mut segmenter = Segmenter::new(request.payload(), Addressing::Normal)
            .map_err(|e| Error::Adapter(e.to_string()))?;
        loop {
            match segmenter.step() {
                Step::Send(frame) => writeln!(
                    self.out,
                    "{:03X} {}",
                    request.target().can_id(),
                    hex(frame.as_bytes())
                )
                .map_err(|e| Error::Adapter(format!("dry run output: {e}")))?,
                Step::WaitForFlowControl => segmenter
                    .flow_control(ASSUMED_FLOW_CONTROL)
                    .map_err(|e| Error::Adapter(e.to_string()))?,
                Step::Done => return Ok(()),
                // The assumed flow control never refuses, so a dry run can't get here.
                Step::Aborted => return Err(Error::Adapter("transfer aborted".into())),
            }
        }
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }
}
