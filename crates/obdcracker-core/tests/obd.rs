//! OBD-II (SAE J1979) request building and reply decoding, from ISO 15765-4 CAN replies.

mod current_data {
    use obdcracker_core::obd::{Reading, Unit, Value, current_data, decode_current_data};
    use obdcracker_core::response::{Error, NegativeResponse, Nrc};

    fn readings(reply: &[u8]) -> Vec<Reading<'_>> {
        decode_current_data(reply)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn quantity(reply: &[u8]) -> (f32, Unit) {
        match readings(reply)[..] {
            [
                Reading {
                    value: Value::Quantity { value, unit },
                    ..
                },
            ] => (value, unit),
            ref other => panic!("{other:?}"),
        }
    }

    #[test]
    fn builds_the_request() {
        assert_eq!(current_data(0x0C), [0x01, 0x0C]);
    }

    #[test]
    fn decodes_engine_speed_vehicle_speed_and_temperatures() {
        assert_eq!(quantity(&[0x41, 0x0C, 0x1A, 0xF8]), (1726.0, Unit::Rpm));
        assert_eq!(
            quantity(&[0x41, 0x0D, 0x32]),
            (50.0, Unit::KilometresPerHour)
        );
        assert_eq!(quantity(&[0x41, 0x05, 0x7B]), (83.0, Unit::Celsius));
        assert_eq!(quantity(&[0x41, 0x0F, 0x00]), (-40.0, Unit::Celsius));
    }

    #[test]
    fn decodes_load_throttle_and_module_voltage() {
        assert_eq!(quantity(&[0x41, 0x04, 0xFF]), (100.0, Unit::Percent));
        assert_eq!(quantity(&[0x41, 0x11, 0x00]), (0.0, Unit::Percent));
        let (volts, unit) = quantity(&[0x41, 0x42, 0x37, 0xE6]);
        assert!((volts - 14.31).abs() < 1e-4, "{volts}");
        assert_eq!(unit, Unit::Volts);
    }

    #[test]
    fn decodes_supported_pid_bitmaps() {
        // Wikipedia's OBD-II PID 00 example
        let [
            Reading {
                pid: 0x00,
                value: Value::Supported(supported),
            },
        ] = readings(&[0x41, 0x00, 0xBE, 0x1F, 0xA8, 0x13])[..]
        else {
            panic!("expected a supported-PID bitmap");
        };
        assert_eq!(
            supported.iter().collect::<Vec<_>>(),
            [
                0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x13, 0x15,
                0x1C, 0x1F, 0x20
            ]
        );
        assert!(supported.contains(0x0C));
        assert!(!supported.contains(0x02));
        assert!(!supported.contains(0x21));
        assert!(supported.contains(0x20), "bit for the next range's bitmap");
    }

    #[test]
    fn decodes_several_pids_in_one_reply() {
        let got = readings(&[0x41, 0x0C, 0x1A, 0xF8, 0x0D, 0x32]);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].pid, got[1].pid), (0x0C, 0x0D));
    }

    #[test]
    fn unknown_pid_takes_the_rest_of_the_reply_raw() {
        // PID 5C, engine oil temperature, isn't in the decoding table
        assert_eq!(
            readings(&[0x41, 0x5C, 0x7B]),
            [Reading {
                pid: 0x5C,
                value: Value::Raw(&[0x7B])
            }]
        );
    }

    #[test]
    fn refusal_truncation_and_empty_replies_are_errors() {
        assert_eq!(
            decode_current_data(&[0x7F, 0x01, 0x12]).err(),
            Some(Error::Negative(NegativeResponse {
                sid: 0x01,
                nrc: Nrc::SubFunctionNotSupported
            }))
        );
        let truncated: Vec<_> = decode_current_data(&[0x41, 0x0C, 0x1A]).unwrap().collect();
        assert_eq!(truncated, [Err(Error::TooShort)]);
        assert_eq!(decode_current_data(&[0x41]).err(), Some(Error::TooShort));
    }
}

mod stored_dtcs {
    use obdcracker_core::obd::{Dtc, decode_stored_dtcs, stored_dtcs};
    use obdcracker_core::response::Error;

    fn codes(reply: &[u8]) -> Vec<String> {
        decode_stored_dtcs(reply)
            .unwrap()
            .map(|dtc| dtc.to_string())
            .collect()
    }

    #[test]
    fn builds_the_request() {
        assert_eq!(stored_dtcs(), [0x03]);
    }

    #[test]
    fn decodes_each_code_after_the_count() {
        // P0401: EGR flow insufficient; P0113: intake air temperature sensor high
        assert_eq!(
            codes(&[0x43, 0x02, 0x04, 0x01, 0x01, 0x13]),
            ["P0401", "P0113"]
        );
        assert_eq!(codes(&[0x43, 0x00]), Vec::<String>::new());
    }

    #[test]
    fn top_bits_pick_the_system_and_the_first_digit() {
        assert_eq!(Dtc::new(0x1234).to_string(), "P1234");
        assert_eq!(Dtc::new(0x4567).to_string(), "C0567");
        assert_eq!(Dtc::new(0x9ABC).to_string(), "B1ABC");
        assert_eq!(Dtc::new(0xC123).to_string(), "U0123");
        assert_eq!(Dtc::new(0xFFFF).to_string(), "U3FFF");
        assert_eq!(Dtc::new(0x0401).code(), 0x0401);
    }

    #[test]
    fn count_must_match_the_codes() {
        assert_eq!(
            decode_stored_dtcs(&[0x43, 0x02, 0x04, 0x01]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(decode_stored_dtcs(&[0x43]).err(), Some(Error::TooShort));
        assert_eq!(
            decode_stored_dtcs(&[0x41, 0x00]).err(),
            Some(Error::WrongService(0x41))
        );
    }
}
