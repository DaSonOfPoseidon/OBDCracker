use proptest::prelude::*;

use super::timing;
use super::wire::{
    self, BitTiming, Body, BtConst, BusError, DeviceConfig, ECHO_ID_RX, FRAME_LEN, Parsed,
};

// A candleLight on an STM32F072: 48 MHz, the limits its firmware reports.
fn candlelight() -> BtConst {
    BtConst {
        feature: 0x0000_0017,
        fclk_can: 48_000_000,
        tseg1_min: 1,
        tseg1_max: 16,
        tseg2_min: 1,
        tseg2_max: 8,
        sjw_max: 4,
        brp_min: 1,
        brp_max: 1024,
        brp_inc: 1,
    }
}

// --- Step 1: golden bytes ---

#[test]
fn control_messages_are_the_bytes_the_device_expects() {
    assert_eq!(wire::host_format(), [0xEF, 0xBE, 0x00, 0x00]);
    assert_eq!(wire::mode_message(wire::MODE_RESET, 0), [0; 8]);
    assert_eq!(
        wire::mode_message(wire::MODE_START, wire::FLAG_LISTEN_ONLY),
        [1, 0, 0, 0, 1, 0, 0, 0]
    );
    assert_eq!(
        wire::mode_message(
            wire::MODE_START,
            wire::FLAG_LISTEN_ONLY | wire::FLAG_BERR_REPORTING
        ),
        [1, 0, 0, 0, 1, 0x10, 0, 0]
    );
    assert_eq!(
        wire::mode_message(wire::MODE_START, 0),
        [1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        (
            wire::BREQ_HOST_FORMAT,
            wire::BREQ_BITTIMING,
            wire::BREQ_MODE,
            wire::BREQ_BT_CONST,
            wire::BREQ_DEVICE_CONFIG
        ),
        (0, 1, 2, 4, 5)
    );
}

#[test]
fn the_device_config_is_twelve_bytes() {
    let bytes = [0, 0, 0, 1, 2, 0, 0, 0, 3, 0, 0, 0];
    assert_eq!(
        DeviceConfig::parse(&bytes).unwrap(),
        DeviceConfig {
            channels: 2,
            sw_version: 2,
            hw_version: 3
        }
    );
    for len in (0..=24).filter(|&len| len != 12) {
        assert!(DeviceConfig::parse(&vec![0; len]).is_err(), "{len}");
    }
}

#[test]
fn the_bit_timing_constants_are_forty_bytes() {
    let mut bytes = Vec::new();
    for word in [0x17_u32, 48_000_000, 1, 16, 1, 8, 4, 1, 1024, 1] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(bytes.len(), 40);
    assert_eq!(BtConst::parse(&bytes).unwrap(), candlelight());
    for len in (0..=64).filter(|&len| len != 40) {
        assert!(BtConst::parse(&vec![0; len]).is_err(), "{len}");
    }
}

#[test]
fn a_bit_timing_message_is_five_words() {
    let timing = BitTiming {
        prop_seg: 6,
        phase_seg1: 7,
        phase_seg2: 2,
        sjw: 1,
        brp: 6,
    };
    assert_eq!(
        timing.to_bytes(),
        [6, 0, 0, 0, 7, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0]
    );
}

#[test]
fn a_transmitted_frame_is_twenty_bytes() {
    let data = [0x02, 0x10, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    assert_eq!(
        wire::encode_tx(3, 0x7E0, false, data),
        [
            3, 0, 0, 0, // echo ID
            0xE0, 0x07, 0, 0, // CAN ID
            8, 0, 0, 0, // DLC 8, channel 0, flags 0, reserved
            0x02, 0x10, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
        ]
    );
    // A 29-bit ID carries the extended flag (bit 31).
    assert_eq!(
        wire::encode_tx(0, 0x18DA_00F1, true, data)[4..8],
        [0xF1, 0x00, 0xDA, 0x98]
    );
    assert_eq!(FRAME_LEN, 20);
}

fn rx_bytes(echo_id: u32, can_id: u32, dlc: u8, channel: u8, flags: u8, data: [u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&echo_id.to_le_bytes());
    bytes.extend_from_slice(&can_id.to_le_bytes());
    bytes.extend_from_slice(&[dlc, channel, flags, 0]);
    bytes.extend_from_slice(&data);
    bytes
}

fn rx(can_id: u32, dlc: u8, data: [u8; 8]) -> Vec<u8> {
    rx_bytes(ECHO_ID_RX, can_id, dlc, 0, 0, data)
}

#[test]
fn a_received_frame_is_parsed() {
    let bytes = rx(0x7E8, 3, [0x03, 0x41, 0x00, 9, 9, 9, 9, 9]);
    assert_eq!(
        wire::parse_frame(&bytes).unwrap(),
        Parsed {
            echo_id: ECHO_ID_RX,
            channel: 0,
            overflow: false,
            body: Body::Data {
                id: 0x7E8,
                extended: false,
                data: vec![0x03, 0x41, 0x00]
            }
        }
    );
    let bytes = rx(0x98DA_F110, 8, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        wire::parse_frame(&bytes).unwrap().body,
        Body::Data {
            id: 0x18DA_F110,
            extended: true,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8]
        }
    );
    // DLC 0 is a frame with no data.
    assert_eq!(
        wire::parse_frame(&rx(0x123, 0, [0; 8])).unwrap().body,
        Body::Data {
            id: 0x123,
            extended: false,
            data: vec![]
        }
    );
}

#[test]
fn a_frame_with_an_echo_id_confirms_a_transmission() {
    let bytes = rx_bytes(7, 0x7E0, 8, 0, 0, [0; 8]);
    let parsed = wire::parse_frame(&bytes).unwrap();
    assert_eq!(parsed.echo_id, 7);
    assert_eq!(parsed.body, Body::Confirmation);
}

#[test]
fn remote_frames_are_not_data() {
    let bytes = rx(0x4000_0000 | 0x7E8, 0, [0; 8]);
    assert_eq!(wire::parse_frame(&bytes).unwrap().body, Body::Remote);
    let bytes = rx(0x4000_0000 | 0x8000_0000 | 0x18DA_F110, 8, [0; 8]);
    assert_eq!(wire::parse_frame(&bytes).unwrap().body, Body::Remote);
}

#[test]
fn the_overflow_flag_is_read_on_any_frame() {
    let bytes = rx_bytes(ECHO_ID_RX, 0x7E8, 1, 0, 1, [0; 8]);
    assert!(wire::parse_frame(&bytes).unwrap().overflow);
    let bytes = rx_bytes(4, 0x7E0, 8, 0, 1, [0; 8]);
    let parsed = wire::parse_frame(&bytes).unwrap();
    assert!(parsed.overflow);
    assert_eq!(parsed.body, Body::Confirmation);
}

#[test]
fn error_frames_map_to_bus_states() {
    let error = |class: u32, detail: u8| {
        let mut data = [0; 8];
        data[1] = detail;
        wire::parse_frame(&rx(0x2000_0000 | class, 8, data))
            .unwrap()
            .body
    };
    assert_eq!(error(0x40, 0), Body::Error(BusError::BusOff));
    // Bus-off wins over any other class bit.
    assert_eq!(error(0x40 | 0x04, 0x10), Body::Error(BusError::BusOff));
    assert_eq!(error(0x04, 0x10), Body::Error(BusError::ErrorPassive));
    assert_eq!(error(0x04, 0x20), Body::Error(BusError::ErrorPassive));
    assert_eq!(error(0x04, 0x01), Body::Error(BusError::Overrun));
    // An overflow beside any other detail or class is still a fault.
    assert_eq!(error(0x04, 0x01 | 0x04), Body::Error(BusError::Other));
    assert_eq!(error(0x04 | 0x80, 0x01), Body::Error(BusError::Other));
    assert_eq!(error(0x04, 0x04), Body::Error(BusError::Other));
    assert_eq!(error(0x80, 0), Body::Error(BusError::Other));
    assert_eq!(error(0x01, 0), Body::Error(BusError::Other));
    assert_eq!(error(0, 0), Body::Error(BusError::Other));
    // An error frame too short to hold the detail byte can't be an overflow or a passive report.
    let mut data = [0; 8];
    data[1] = 0x01;
    assert_eq!(
        wire::parse_frame(&rx(0x2000_0004, 1, data)).unwrap().body,
        Body::Error(BusError::Other)
    );
}

// --- Step 2: the parser takes anything ---

#[test]
fn only_a_twenty_byte_frame_is_accepted() {
    for len in 0..=64 {
        let bytes = vec![0; len];
        assert_eq!(wire::parse_frame(&bytes).is_ok(), len == FRAME_LEN, "{len}");
    }
    // A timestamp (24 bytes) wasn't asked for.
    assert!(wire::parse_frame(&rx(0x7E8, 8, [0; 8]).repeat(2)).is_err());
}

#[test]
fn every_dlc_above_eight_is_refused() {
    for dlc in 0..=255_u8 {
        let result = wire::parse_frame(&rx(0x7E8, dlc, [0; 8]));
        assert_eq!(result.is_ok(), dlc <= 8, "{dlc}");
        let result = wire::parse_frame(&rx(0x2000_0040, dlc, [0; 8]));
        assert_eq!(result.is_ok(), dlc <= 8, "error frame, {dlc}");
    }
}

#[test]
fn only_the_overflow_flag_is_accepted() {
    for flags in 0..=255_u8 {
        let result = wire::parse_frame(&rx_bytes(ECHO_ID_RX, 0x7E8, 8, 0, flags, [0; 8]));
        assert_eq!(result.is_ok(), flags <= 1, "{flags:#04x}");
    }
}

#[test]
fn an_eleven_bit_id_with_higher_bits_is_refused() {
    assert!(wire::parse_frame(&rx(0x800, 8, [0; 8])).is_err());
    assert!(wire::parse_frame(&rx(0x1000_0000, 8, [0; 8])).is_err());
    assert!(wire::parse_frame(&rx(0x7FF, 8, [0; 8])).is_ok());
    assert!(wire::parse_frame(&rx(0x8000_0800, 8, [0; 8])).is_ok());
}

proptest! {
    #[test]
    fn the_frame_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = wire::parse_frame(&bytes);
    }

    #[test]
    fn what_the_parser_accepts_is_a_classic_frame(bytes in proptest::collection::vec(any::<u8>(), 20)) {
        if let Ok(parsed) = wire::parse_frame(&bytes) {
            if let Body::Data { id, extended, data } = parsed.body {
                prop_assert!(data.len() <= 8);
                let limit = if extended { 0x1FFF_FFFF } else { 0x7FF };
                prop_assert!(id <= limit);
            }
            prop_assert!(bytes[10] <= 1);
            prop_assert!(bytes[8] <= 8);
        }
    }

    #[test]
    fn the_control_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
        let _ = DeviceConfig::parse(&bytes);
        let _ = BtConst::parse(&bytes);
    }

    #[test]
    fn a_frame_we_encode_is_what_a_device_would_echo(
        echo in 0u32..10,
        id in 0u32..=0x7FF,
        data in proptest::array::uniform8(any::<u8>()),
    ) {
        let bytes = wire::encode_tx(echo, id, false, data);
        let parsed = wire::parse_frame(&bytes).unwrap();
        prop_assert_eq!(parsed.echo_id, echo);
        prop_assert_eq!(parsed.body, Body::Confirmation);
        prop_assert_eq!(&bytes[12..], &data[..]);
    }
}

// --- The bit timing ---

#[test]
fn a_48_mhz_clock_gets_the_usual_timings() {
    let at_500k = timing::compute(500_000, &candlelight()).unwrap();
    // 16 time quanta of 125 ns: sample point (1 + 13) / 16 = 87.5%.
    assert_eq!(
        at_500k,
        BitTiming {
            prop_seg: 6,
            phase_seg1: 7,
            phase_seg2: 2,
            sjw: 1,
            brp: 6
        }
    );
    let at_250k = timing::compute(250_000, &candlelight()).unwrap();
    assert_eq!((at_250k.brp, at_250k.phase_seg2), (12, 2));
    assert_eq!(at_250k.prop_seg + at_250k.phase_seg1, 13);
}

#[test]
fn a_timing_is_exact_and_within_the_device_limits() {
    for fclk in [
        8_000_000, 16_000_000, 24_000_000, 40_000_000, 48_000_000, 80_000_000,
    ] {
        for bitrate in [250_000, 500_000] {
            let c = BtConst {
                fclk_can: fclk,
                ..candlelight()
            };
            let t = timing::compute(bitrate, &c).unwrap();
            let tseg1 = t.prop_seg + t.phase_seg1;
            let quanta = 1 + tseg1 + t.phase_seg2;
            assert_eq!(fclk / (t.brp * quanta), bitrate, "{fclk} {bitrate}");
            assert_eq!(fclk % (t.brp * quanta), 0, "{fclk} {bitrate}");
            assert!((c.tseg1_min..=c.tseg1_max).contains(&tseg1));
            assert!((c.tseg2_min..=c.tseg2_max).contains(&t.phase_seg2));
            assert!((c.brp_min..=c.brp_max).contains(&t.brp));
            assert!(t.sjw >= 1 && t.sjw <= c.sjw_max && t.sjw <= t.phase_seg2);
            let sample = (1 + tseg1) * 1000 / quanta;
            assert!((750..=900).contains(&sample), "{fclk} {bitrate} {sample}");
        }
    }
}

#[test]
fn a_bitrate_the_clock_cannot_reach_exactly_is_refused() {
    // 18.5 MHz / 500 kbit/s = 37 clocks per bit, a prime: one prescaler step would need 37 time
    // quanta, and the device allows 25.
    for fclk in [18_500_000, 7_999_999, 48_000_001, 1, 0] {
        let c = BtConst {
            fclk_can: fclk,
            ..candlelight()
        };
        assert!(timing::compute(500_000, &c).is_err(), "{fclk}");
    }
    assert!(timing::compute(0, &candlelight()).is_err());
    // 48 MHz / 400 kbit/s = 120 = 15 * 8: it can be done, so it isn't refused for the clock.
    assert!(timing::compute(400_000, &candlelight()).is_ok());
}

#[test]
fn limits_that_leave_no_timing_refuse_it() {
    let c = |f: &dyn Fn(&mut BtConst)| {
        let mut c = candlelight();
        f(&mut c);
        timing::compute(500_000, &c)
    };
    // The prescaler can't be 6.
    assert!(c(&|c| c.brp_min = 33).is_err());
    assert!(c(&|c| c.brp_max = 5).is_err());
    // A step of 5 from 1 allows 1, 6, 11, ...: 6 is allowed.
    assert!(c(&|c| c.brp_inc = 5).is_ok());
    // A step of 4 from 1 allows 1, 5, 9, 13: no divisor of 96 that gives a usable bit is there.
    assert!(c(&|c| c.brp_inc = 4).is_err());
    // A device that reports no step is taken to mean 1.
    assert!(c(&|c| c.brp_inc = 0).is_ok());
    // No time quanta fit.
    assert!(c(&|c| c.tseg1_max = 0).is_err());
    assert!(c(&|c| c.tseg2_max = 0).is_err());
    assert!(c(&|c| c.tseg2_min = 9).is_err());
    assert!(c(&|c| c.sjw_max = 0).is_err());
    // Absurd limits don't make it loop or overflow.
    assert!(
        c(&|c| {
            c.tseg1_max = u32::MAX;
            c.tseg2_max = u32::MAX;
            c.brp_max = u32::MAX;
        })
        .is_ok()
    );
    assert!(
        c(&|c| {
            c.fclk_can = u32::MAX;
            c.tseg1_min = u32::MAX;
        })
        .is_err()
    );
}

#[test]
fn a_sample_point_far_from_the_standard_is_refused() {
    // Only 4 time quanta fit, so the sample point is 50% or 75% or 100%.
    let c = BtConst {
        fclk_can: 2_000_000,
        tseg1_max: 2,
        tseg2_max: 1,
        ..candlelight()
    };
    assert!(timing::compute(500_000, &c).is_ok());
    let c = BtConst {
        tseg1_max: 1,
        tseg2_max: 2,
        tseg2_min: 2,
        fclk_can: 2_000_000,
        ..candlelight()
    };
    assert!(timing::compute(500_000, &c).is_err());
}

proptest! {
    #[test]
    fn any_timing_found_is_exact(
        fclk in 1_000_000u32..200_000_000,
        t1max in 0u32..40,
        t2max in 0u32..20,
        brp_max in 0u32..2048,
        inc in 0u32..8,
        bitrate in prop::sample::select(vec![250_000u32, 500_000]),
    ) {
        let c = BtConst {
            fclk_can: fclk,
            tseg1_max: t1max,
            tseg2_max: t2max,
            brp_max,
            brp_inc: inc,
            ..candlelight()
        };
        if let Ok(t) = timing::compute(bitrate, &c) {
            let quanta = u64::from(1 + t.prop_seg + t.phase_seg1 + t.phase_seg2);
            prop_assert_eq!(u64::from(fclk), u64::from(bitrate) * u64::from(t.brp) * quanta);
            prop_assert!(t.brp >= c.brp_min && t.brp <= c.brp_max);
            prop_assert!(t.prop_seg + t.phase_seg1 <= t1max);
            prop_assert!(t.phase_seg2 <= t2max);
        }
    }
}
