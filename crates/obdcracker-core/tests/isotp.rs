//! ISO-TP framing against ISO 15765-2 examples.

use obdcracker_core::isotp::single_frame;

#[test]
fn prefixes_the_payload_with_its_length() {
    // ISO 15765-2 single frame: PCI nibble 0, length nibble, then data. Mode 09 PID 02 (VIN).
    assert_eq!(
        single_frame(&[0x09, 0x02]).unwrap().as_bytes(),
        [0x02, 0x09, 0x02]
    );
}

#[test]
fn fits_up_to_seven_bytes() {
    let payload = [0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x90];
    let frame = single_frame(&payload).unwrap();
    assert_eq!(frame.as_bytes()[0], 0x07);
    assert_eq!(&frame.as_bytes()[1..], payload);
}

#[test]
fn refuses_empty_and_oversized_payloads() {
    assert_eq!(single_frame(&[]), None);
    assert_eq!(single_frame(&[0; 8]), None);
}
