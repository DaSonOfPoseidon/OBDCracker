//! Splits the input into CAN frames and feeds them to a reassembler, which must never panic or
//! return a payload longer than its buffer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use obdcracker_core::isotp::{Addressing, Frame, Progress, Reassembler};

fuzz_target!(|data: &[u8]| {
    // The first byte picks the addressing, the second the buffer size; each frame after that is
    // a length byte (0 to 15, so oversized frames are tried too) and its data.
    let [mode, size, rest @ ..] = data else {
        return;
    };
    let mut rest = rest;
    let addressing = if mode & 1 == 0 {
        Addressing::Normal
    } else {
        Addressing::Extended(mode >> 1)
    };
    let mut buf = vec![0; usize::from(*size) * 32];
    let capacity = buf.len();
    let mut rx = Reassembler::new(buf.as_mut_slice(), addressing);
    while let [len, tail @ ..] = rest {
        let len = usize::from(len & 0x0F).min(tail.len());
        let (frame, tail) = tail.split_at(len);
        rest = tail;
        let _ = Frame::parse(frame, addressing);
        if let Ok(Progress::Complete(payload)) = rx.feed(frame) {
            assert!(payload.len() <= capacity);
        }
    }
});
