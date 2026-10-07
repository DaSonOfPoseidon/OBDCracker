use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_safety::Approved;

use crate::{Error, Response, Transport};

/// Records what is sent and replies from a queue. For tests; never touches hardware.
#[derive(Debug, Default)]
pub struct Mock {
    sent: Vec<Approved>,
    replies: VecDeque<Response>,
}

impl Mock {
    pub fn queue(&mut self, response: Response) {
        self.replies.push_back(response);
    }

    #[must_use]
    pub fn sent(&self) -> &[Approved] {
        &self.sent
    }
}

impl Transport for Mock {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.sent.push(request.clone());
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}
