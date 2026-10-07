use std::time::Duration;

use obdcracker_core::isotp::single_frame;
use obdcracker_safety::Approved;
use obdcracker_transport::{Error, Response, Transport};

use crate::audit::hex;

/// Prints the CAN frame each request would put on the bus and never opens a device.
#[derive(Debug)]
pub struct DryRun;

impl Transport for DryRun {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let frame = single_frame(request.payload())
            .ok_or_else(|| Error::Adapter("multi-frame requests aren't supported yet".into()))?;
        println!(
            "{:03X} {}",
            request.target().can_id(),
            hex(frame.as_bytes())
        );
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        Err(Error::Timeout)
    }
}
