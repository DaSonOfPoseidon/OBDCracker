//! SocketCAN's frames, byte for byte.

use proptest::prelude::*;

use super::device::KernelFilter;
use super::linux::{parse_decimal, parse_flags};
use super::wire::{
    Body, BusError, EFF_FLAG, ERROR_MASK, FRAME_LEN, RTR_FLAG, encode_tx, exact_filter,
    kernel_filter, parse_frame,
};
use crate::raw::port::Filter;

fn raw(can_id: u32, dlc: u8, data: [u8; 8]) -> Vec<u8> {
    let mut bytes = vec![0; FRAME_LEN];
    bytes[0..4].copy_from_slice(&can_id.to_ne_bytes());
    bytes[4] = dlc;
    bytes[8..].copy_from_slice(&data);
    bytes
}

#[test]
fn a_transmitted_frame_is_sixteen_bytes_with_dlc_eight() {
    let bytes = encode_tx(0x7E0, false, [2, 0x10, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
    assert_eq!(bytes.len(), 16);
    assert_eq!(bytes[0..4], 0x7E0u32.to_ne_bytes());
    assert_eq!(bytes[4], 8);
    assert_eq!(bytes[5..8], [0, 0, 0]);
    assert_eq!(bytes[8..], [2, 0x10, 1, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
}

#[test]
fn an_extended_frame_carries_the_extended_flag() {
    let bytes = encode_tx(0x17FC_0010, true, [0; 8]);
    assert_eq!(bytes[0..4], (0x17FC_0010u32 | EFF_FLAG).to_ne_bytes());
}

#[test]
fn a_received_frame_is_parsed() {
    assert_eq!(
        parse_frame(&raw(0x7E8, 8, [0x10, 0x14, 0x49, 2, 1, 0x57, 0x41, 0x55])).unwrap(),
        Body::Data {
            id: 0x7E8,
            extended: false,
            data: vec![0x10, 0x14, 0x49, 2, 1, 0x57, 0x41, 0x55]
        }
    );
    assert_eq!(
        parse_frame(&raw(0x17FE_0010 | EFF_FLAG, 3, [1, 2, 3, 0, 0, 0, 0, 0])).unwrap(),
        Body::Data {
            id: 0x17FE_0010,
            extended: true,
            data: vec![1, 2, 3]
        }
    );
    // A frame of no data is a frame.
    assert_eq!(
        parse_frame(&raw(0x123, 0, [0; 8])).unwrap(),
        Body::Data {
            id: 0x123,
            extended: false,
            data: vec![]
        }
    );
}

#[test]
fn remote_frames_are_not_data() {
    assert_eq!(
        parse_frame(&raw(0x7E8 | RTR_FLAG, 0, [0; 8])).unwrap(),
        Body::Remote
    );
}

#[test]
fn error_frames_map_to_bus_states() {
    let error = |class: u32, dlc: u8, detail: u8| {
        parse_frame(&raw(
            0x2000_0000 | class,
            dlc,
            [0, detail, 0, 0, 0, 0, 0, 0],
        ))
        .unwrap()
    };
    assert_eq!(error(0x040, 8, 0), Body::Error(BusError::BusOff));
    // Bus-off wins over anything else in the same frame.
    assert_eq!(error(0x040 | 0x004, 8, 0x10), Body::Error(BusError::BusOff));
    assert_eq!(error(0x004, 8, 0x10), Body::Error(BusError::ErrorPassive));
    assert_eq!(error(0x004, 8, 0x20), Body::Error(BusError::ErrorPassive));
    // A state change comes with the error counters' class bit.
    assert_eq!(
        error(0x004 | 0x200, 8, 0x10),
        Body::Error(BusError::ErrorPassive)
    );
    assert_eq!(error(0x004, 8, 0x01), Body::Error(BusError::Overrun));
    // An overflow with anything else beside it isn't just an overrun.
    assert_eq!(error(0x004, 8, 0x01 | 0x04), Body::Error(BusError::Other));
    assert_eq!(error(0x004 | 0x200, 8, 0x01), Body::Error(BusError::Other));
    for other in [0x001, 0x008, 0x010, 0x020, 0x080, 0x100, 0x200] {
        assert_eq!(
            error(other, 8, 0),
            Body::Error(BusError::Other),
            "{other:#x}"
        );
    }
    // The controller detail is only read from a frame of the length the kernel gives it.
    assert_eq!(error(0x004, 4, 0x10), Body::Error(BusError::Other));
    // An error frame with no class is still an error on the bus.
    assert_eq!(error(0, 8, 0), Body::Error(BusError::Other));
}

#[test]
fn the_error_mask_asks_for_everything_but_a_lost_arbitration() {
    assert_eq!(ERROR_MASK & 0x002, 0);
    for class in [
        0x001, 0x004, 0x008, 0x010, 0x020, 0x040, 0x080, 0x100, 0x200,
    ] {
        assert_ne!(ERROR_MASK & class, 0, "{class:#x}");
    }
    assert_eq!(ERROR_MASK & !0x3FF, 0);
}

#[test]
fn only_a_sixteen_byte_frame_is_accepted() {
    for len in [0, 1, 8, 15, 17, 24, 72] {
        assert!(parse_frame(&vec![0; len]).is_err(), "{len}");
    }
}

#[test]
fn every_dlc_above_eight_is_refused() {
    for dlc in 9..=255u8 {
        let err = parse_frame(&raw(0x7E8, dlc, [0; 8])).unwrap_err();
        assert!(err.contains("above 8"), "{err}");
    }
    for dlc in 0..=8 {
        assert!(parse_frame(&raw(0x7E8, dlc, [0; 8])).is_ok());
    }
}

#[test]
fn an_eleven_bit_id_with_higher_bits_is_refused() {
    assert!(parse_frame(&raw(0x800, 8, [0; 8])).is_err());
    assert!(parse_frame(&raw(0x1FFF_F800, 8, [0; 8])).is_err());
    assert!(parse_frame(&raw(0x7FF, 8, [0; 8])).is_ok());
    // The same bits are fine in a 29-bit frame.
    assert!(parse_frame(&raw(0x800 | EFF_FLAG, 8, [0; 8])).is_ok());
}

#[test]
fn kernel_filters_carry_the_width_in_the_mask() {
    // An 11-bit filter must not pass a 29-bit frame with the same low bits, nor a remote frame.
    let f = kernel_filter(&Filter {
        id: 0x7E8,
        mask: 0x7F8,
        extended: false,
    });
    assert_eq!(
        f,
        KernelFilter {
            id: 0x7E8,
            mask: 0x7F8 | EFF_FLAG | RTR_FLAG
        }
    );
    let pass = |f: KernelFilter, id: u32| id & f.mask == f.id & f.mask;
    assert!(pass(f, 0x7EF));
    assert!(!pass(f, 0x7EF | EFF_FLAG));
    assert!(!pass(f, 0x7EF | RTR_FLAG));
    assert!(!pass(f, 0x7F0));

    let f = kernel_filter(&Filter {
        id: 0x17FE_0010,
        mask: 0x1FFF_FFFF,
        extended: true,
    });
    assert!(pass(f, 0x17FE_0010 | EFF_FLAG));
    assert!(!pass(f, 0x17FE_0010));
    assert!(!pass(f, 0x17FE_0011 | EFF_FLAG));
}

#[test]
fn a_filter_wider_than_its_width_is_cut_to_it() {
    let f = kernel_filter(&Filter {
        id: 0xFFFF_FFFF,
        mask: 0xFFFF_FFFF,
        extended: false,
    });
    assert_eq!(f.id, 0x7FF);
    assert_eq!(f.mask, 0x7FF | EFF_FLAG | RTR_FLAG);
}

#[test]
fn an_exact_filter_passes_one_id_at_one_width() {
    let pass = |f: KernelFilter, id: u32| id & f.mask == f.id & f.mask;
    let f = exact_filter(0x7E0, false);
    assert!(pass(f, 0x7E0));
    assert!(!pass(f, 0x7E1));
    assert!(!pass(f, 0x7E0 | EFF_FLAG));
    let f = exact_filter(0x7E0, true);
    assert!(pass(f, 0x7E0 | EFF_FLAG));
    assert!(!pass(f, 0x7E0));
}

#[test]
fn sysfs_numbers_are_strict() {
    assert_eq!(parse_decimal("280\n"), Some(280));
    assert_eq!(parse_decimal("0\n"), Some(0));
    for bad in [
        "", "\n", "280", "+280\n", "-1\n", "28 0\n", "280\n\n", "0x118\n", " 280\n", "٣\n",
    ] {
        assert_eq!(parse_decimal(bad), None, "{bad:?}");
    }
    assert_eq!(parse_decimal("18446744073709551615\n"), Some(u64::MAX));
    assert_eq!(parse_decimal("18446744073709551616\n"), None);
}

#[test]
fn sysfs_flags_are_strict() {
    assert_eq!(parse_flags("0x1003\n"), Some(0x1003));
    assert_eq!(parse_flags("0x41003\n"), Some(0x41003));
    assert_eq!(parse_flags("0xFFFFFFFF\n"), Some(u32::MAX));
    for bad in [
        "",
        "\n",
        "1003\n",
        "0x\n",
        "0x+1\n",
        "0x 1\n",
        "0X1003\n",
        "0x1003",
        "0x1003\n\n",
        "0x100000000\n",
        "0xg\n",
    ] {
        assert_eq!(parse_flags(bad), None, "{bad:?}");
    }
}

proptest! {
    #[test]
    fn the_frame_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
        let _ = parse_frame(&bytes);
    }

    #[test]
    fn what_the_parser_accepts_is_a_classic_frame(bytes in proptest::collection::vec(any::<u8>(), 16)) {
        match parse_frame(&bytes) {
            Ok(Body::Data { id, extended, data }) => {
                prop_assert!(data.len() <= 8);
                let limit = if extended { 0x1FFF_FFFF } else { 0x7FF };
                prop_assert!(id <= limit);
            }
            Ok(Body::Remote | Body::Error(_)) => {}
            Err(_) => {}
        }
    }

    #[test]
    fn a_frame_we_encode_is_what_the_kernel_would_hand_back(
        id in 0u32..=0x1FFF_FFFF,
        extended in any::<bool>(),
        data in any::<[u8; 8]>(),
    ) {
        let id = if extended { id } else { id & 0x7FF };
        let parsed = parse_frame(&encode_tx(id, extended, data)).unwrap();
        prop_assert_eq!(parsed, Body::Data { id, extended, data: data.to_vec() });
    }

    #[test]
    fn a_filter_passes_what_it_describes(
        id in any::<u32>(),
        mask in any::<u32>(),
        extended in any::<bool>(),
        frame_id in any::<u32>(),
    ) {
        let filter = Filter { id, mask, extended };
        let f = kernel_filter(&filter);
        let width = if extended { 0x1FFF_FFFF } else { 0x7FF };
        let flags = if extended { EFF_FLAG } else { 0 };
        let candidate = (frame_id & width) | flags;
        let kernel = candidate & f.mask == f.id & f.mask;
        let wanted = (frame_id & width) & mask & width == id & mask & width;
        prop_assert_eq!(kernel, wanted);
        // Never a frame of the other width, and never a remote one.
        prop_assert!(candidate & f.mask != f.id & f.mask || candidate & EFF_FLAG == flags);
        prop_assert!((candidate | RTR_FLAG) & f.mask != f.id & f.mask);
    }
}
