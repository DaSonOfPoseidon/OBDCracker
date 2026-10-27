//! A simulated VW TP2.0 module ([`crate::SimBus::add_tp20`]): it opens a channel, answers the
//! tester's parameters and keep-alives, and answers KWP2000 requests in data frames, holding
//! each block until the tester ACKs it.

use std::collections::VecDeque;

use obdcracker_core::tp20::{self, Channel, Frame};

// The module's channel parameters: block size 15, T1 100 ms, T3 5 ms.
pub(crate) const PARAMETERS: [u8; 6] = [0xA1, 0x0F, 0x8A, 0xFF, 0x32, 0xFF];
// KWP2000 refusals: service not supported, request out of range.
const NOT_SUPPORTED: u8 = 0x11;
const OUT_OF_RANGE: u8 = 0x31;

#[derive(Debug)]
pub(crate) struct Tp20Module {
    pub(crate) address: u8,
    pub(crate) channel: Channel,
    pub(crate) open: bool,
    // KWP2000 requests and the module's answers.
    pub(crate) answers: Vec<(Vec<u8>, Vec<u8>)>,
    // Which frame of the next answer the adapter loses, if any.
    pub(crate) lose: Option<usize>,
    // How many frames the tester takes before it wants an ACK, from its `A0`.
    block_size: u8,
    // The sequence numbers of the tester's next data frame and of the module's.
    tester_sequence: u8,
    sequence: u8,
    // The module's frames that wait for the tester's ACK.
    held: VecDeque<Vec<u8>>,
}

impl Tp20Module {
    pub(crate) fn new(address: u8, channel: Channel) -> Self {
        Self {
            address,
            channel,
            open: false,
            answers: Vec::new(),
            lose: None,
            block_size: 15,
            tester_sequence: 0,
            sequence: 0,
            held: VecDeque::new(),
        }
    }

    // A setup to its address opens a fresh channel.
    pub(crate) fn open(&mut self) {
        self.open = true;
        self.block_size = 15;
        self.tester_sequence = 0;
        self.sequence = 0;
        self.held.clear();
    }

    // What the module sends in answer to the tester's `frame` on its open channel.
    pub(crate) fn hear(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        match frame {
            [0xA0, block, ..] => {
                self.block_size = (block & 0x0F).max(1);
                vec![PARAMETERS.to_vec()]
            }
            [0xA3] => vec![PARAMETERS.to_vec()],
            [0xA8] => {
                self.open = false;
                vec![tp20::DISCONNECT.to_vec()]
            }
            _ => match Frame::parse(frame) {
                Ok(Frame::Ack { next, ready: true }) => self.release(next),
                // One frame holds the whole request: its length, then the request.
                Ok(Frame::Data {
                    sequence,
                    last: true,
                    bytes: [high, low, request @ ..],
                    ..
                }) if sequence == self.tester_sequence
                    && !request.is_empty()
                    && usize::from(u16::from_be_bytes([*high, *low])) == request.len() =>
                {
                    self.tester_sequence = (sequence + 1) & 0x0F;
                    let mut sent = vec![tp20::ack(self.tester_sequence).to_vec()];
                    let answer = self.answer(request);
                    self.held = self.frames(&answer);
                    sent.extend(self.next_block());
                    sent
                }
                _ => Vec::new(),
            },
        }
    }

    fn answer(&self, request: &[u8]) -> Vec<u8> {
        if let Some((_, answer)) = self.answers.iter().find(|(asked, _)| asked == request) {
            return answer.clone();
        }
        let sid = request[0];
        let known = self.answers.iter().any(|(asked, _)| asked[0] == sid);
        vec![0x7F, sid, if known { OUT_OF_RANGE } else { NOT_SUPPORTED }]
    }

    // `message` as data frames: its 2-byte length first, 7 bytes a frame, asking for an ACK
    // after every block and on the last. The frame the adapter loses is left out.
    fn frames(&mut self, message: &[u8]) -> VecDeque<Vec<u8>> {
        // `add_tp20_answer` keeps answers within the 2-byte length.
        let mut data = u16::try_from(message.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes()
            .to_vec();
        data.extend_from_slice(message);
        let count = data.len().div_ceil(7);
        let mut frames: VecDeque<Vec<u8>> = data
            .chunks(7)
            .enumerate()
            .map(|(index, chunk)| {
                let last = index + 1 == count;
                let wants_ack = last || (index + 1) % usize::from(self.block_size) == 0;
                let op = match (wants_ack, last) {
                    (true, false) => 0x0,
                    (true, true) => 0x1,
                    (false, false) => 0x2,
                    (false, true) => 0x3,
                };
                let mut frame = vec![op << 4 | self.sequence];
                frame.extend_from_slice(chunk);
                self.sequence = (self.sequence + 1) & 0x0F;
                frame
            })
            .collect();
        if let Some(index) = self.lose.take()
            && index < frames.len()
        {
            frames.remove(index);
        }
        frames
    }

    // The held frames up to the next that asks for an ACK.
    fn next_block(&mut self) -> Vec<Vec<u8>> {
        let mut block = Vec::new();
        while let Some(frame) = self.held.pop_front() {
            let wants_ack = frame[0] >> 4 <= 0x1;
            block.push(frame);
            if wants_ack {
                break;
            }
        }
        block
    }

    // The tester is ready for the frame with sequence number `next`: the next block, if it's
    // the one held.
    fn release(&mut self, next: u8) -> Vec<Vec<u8>> {
        match self.held.front() {
            Some(frame) if frame[0] & 0x0F == next => self.next_block(),
            _ => Vec::new(),
        }
    }
}
