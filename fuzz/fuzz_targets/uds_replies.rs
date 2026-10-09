//! Every UDS decoder on arbitrary replies, including multi-DID reads with a layout taken from
//! the input: they return errors and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use obdcracker_core::{response, uds};

fuzz_target!(|data: &[u8]| {
    // The first byte gives how many 3-byte layout entries (DID, data length) follow; the rest
    // is the reply. Lengths up to 255 let the layout line up with the reply's bytes.
    let [count, rest @ ..] = data else {
        return;
    };
    let (entries, _) = rest.as_chunks::<3>();
    let entries = &entries[..usize::from(count % 5).min(entries.len())];
    let reply = &rest[entries.len() * 3..];
    let layout: Vec<(u16, usize)> = entries
        .iter()
        .map(|&[high, low, len]| (u16::from_be_bytes([high, low]), usize::from(len)))
        .collect();

    let _ = response::positive(0x22, reply);
    // The DID the reply echoes, so decoding gets past the DID check.
    if let Some(&did) = reply.get(1..).and_then(<[u8]>::first_chunk::<2>) {
        let _ = uds::decode_did(reply, u16::from_be_bytes(did));
    }
    if let Ok(values) = uds::decode_dids(reply, &layout) {
        values.for_each(drop);
    }
    let _ = uds::decode_text(reply);
    if let Ok(count) = uds::decode_dtc_count(reply) {
        let _ = uds::UdsDtc::new(0x04_01_00).j2012(count.format);
    }
    for decode in [uds::decode_dtcs_by_status_mask, uds::decode_supported_dtcs] {
        if let Ok((_, records)) = decode(reply) {
            records.for_each(|record| drop(record.dtc.to_string()));
        }
    }
});
