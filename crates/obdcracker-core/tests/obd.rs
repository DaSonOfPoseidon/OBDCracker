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

    // Within float rounding of `want`.
    fn assert_quantity(reply: &[u8], want: f32, want_unit: Unit) {
        let (value, unit) = quantity(reply);
        assert!(
            (value - want).abs() < 1e-3 && unit == want_unit,
            "{reply:02X?}: {value} {unit:?}, want {want} {want_unit:?}"
        );
    }

    #[test]
    fn decodes_the_scalar_pids_the_a7_supports() {
        // The bytes the A7's engine sent in #49 (engine off), and the formulas from SAE J1979.
        for (reply, value, unit) in [
            (&[0x41, 0x10, 0x00, 0xEC][..], 2.36, Unit::GramsPerSecond),
            (&[0x41, 0x1F, 0x00, 0x00], 0.0, Unit::Seconds),
            (&[0x41, 0x21, 0x00, 0x00], 0.0, Unit::Kilometres),
            (&[0x41, 0x30, 0xED], 237.0, Unit::Count),
            (&[0x41, 0x31, 0x1C, 0xC3], 7363.0, Unit::Kilometres),
            (&[0x41, 0x33, 0x62], 98.0, Unit::Kilopascals),
            (&[0x41, 0x3C, 0x00, 0x00], -40.0, Unit::Celsius),
            (&[0x41, 0x3E, 0x02, 0xC6], 31.0, Unit::Celsius),
            (&[0x41, 0x45, 0xFF], 100.0, Unit::Percent),
            (&[0x41, 0x46, 0x47], 31.0, Unit::Celsius),
            (&[0x41, 0x49, 0x26], 14.901_96, Unit::Percent),
            (&[0x41, 0x4A, 0x26], 14.901_96, Unit::Percent),
            (&[0x41, 0x4C, 0xFF], 100.0, Unit::Percent),
            (&[0x41, 0x5C, 0x61], 57.0, Unit::Celsius),
            (&[0x41, 0x5D, 0x69, 0x00], 0.0, Unit::Degrees),
            (&[0x41, 0x5E, 0x00, 0x00], 0.0, Unit::LitresPerHour),
            (&[0x41, 0x61, 0x74], -9.0, Unit::Percent),
            (&[0x41, 0x62, 0x7D], 0.0, Unit::Percent),
            (&[0x41, 0x63, 0x02, 0x44], 580.0, Unit::NewtonMetres),
        ] {
            assert_quantity(reply, value, unit);
        }
    }

    #[test]
    fn scalar_pids_reach_their_formula_limits() {
        for (reply, value, unit) in [
            (&[0x41, 0x10, 0xFF, 0xFF][..], 655.35, Unit::GramsPerSecond),
            (&[0x41, 0x1F, 0xFF, 0xFF], 65535.0, Unit::Seconds),
            (&[0x41, 0x30, 0xFF], 255.0, Unit::Count),
            (&[0x41, 0x3C, 0xFF, 0xFF], 6513.5, Unit::Celsius),
            (&[0x41, 0x46, 0x00], -40.0, Unit::Celsius),
            (&[0x41, 0x5D, 0x00, 0x00], -210.0, Unit::Degrees),
            (&[0x41, 0x5D, 0xFF, 0xFF], 301.992_2, Unit::Degrees),
            (&[0x41, 0x5E, 0xFF, 0xFF], 3276.75, Unit::LitresPerHour),
            (&[0x41, 0x61, 0x00], -125.0, Unit::Percent),
            (&[0x41, 0x62, 0xFF], 130.0, Unit::Percent),
            (&[0x41, 0x63, 0xFF, 0xFF], 65535.0, Unit::NewtonMetres),
        ] {
            assert_quantity(reply, value, unit);
        }
    }

    #[test]
    fn scalar_pids_need_their_full_length() {
        for reply in [
            &[0x41, 0x10, 0x00][..],
            &[0x41, 0x31, 0x1C],
            &[0x41, 0x3E, 0x02],
            &[0x41, 0x5D, 0x69],
            &[0x41, 0x63, 0x02],
            &[0x41, 0x30],
        ] {
            let mut readings = decode_current_data(reply).unwrap();
            assert!(
                matches!(readings.next(), Some(Err(_))),
                "{reply:02X?} should be an error"
            );
        }
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
        // SAE J1979 doesn't define PID E1, so no decoder ever will.
        assert_eq!(
            readings(&[0x41, 0xE1, 0x7B]),
            [Reading {
                pid: 0xE1,
                value: Value::Raw(&[0x7B])
            }]
        );
    }

    #[test]
    fn unknown_pid_without_data_is_truncated() {
        let got: Vec<_> = decode_current_data(&[0x41, 0xE1]).unwrap().collect();
        assert_eq!(got, [Err(Error::TooShort)]);
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
        assert_eq!(
            codes(&[0x43, 0x02, 0x04, 0x01, 0x01, 0x13]),
            ["P0401", "P0113"]
        );
        assert_eq!(codes(&[0x43, 0x00]), Vec::<String>::new());
    }

    #[test]
    fn p0000_is_padding_not_a_code() {
        assert_eq!(codes(&[0x43, 0x01, 0x00, 0x00]), Vec::<String>::new());
        assert_eq!(
            codes(&[0x43, 0x03, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00]),
            ["P0401"]
        );
    }

    #[test]
    fn padding_still_counts_toward_the_count() {
        assert_eq!(
            decode_stored_dtcs(&[0x43, 0x02, 0x00, 0x00]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_stored_dtcs(&[0x43, 0x01, 0x00, 0x00, 0x00]).err(),
            Some(Error::Malformed)
        );
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

mod pending_and_permanent_dtcs {
    use obdcracker_core::obd::{
        decode_pending_dtcs, decode_permanent_dtcs, decode_stored_dtcs, pending_dtcs,
        permanent_dtcs,
    };
    use obdcracker_core::response::{Error, NegativeResponse, Nrc};

    #[test]
    fn builds_the_requests() {
        assert_eq!(pending_dtcs(), [0x07]);
        assert_eq!(permanent_dtcs(), [0x0A]);
    }

    #[test]
    fn decodes_codes_skipping_padding() {
        let pending: Vec<_> = decode_pending_dtcs(&[0x47, 0x02, 0x04, 0x01, 0x00, 0x00])
            .unwrap()
            .map(|dtc| dtc.to_string())
            .collect();
        assert_eq!(pending, ["P0401"]);
        let permanent: Vec<_> = decode_permanent_dtcs(&[0x4A, 0x02, 0x01, 0x13, 0xC1, 0x00])
            .unwrap()
            .map(|dtc| dtc.to_string())
            .collect();
        assert_eq!(permanent, ["P0113", "U0100"]);
        assert_eq!(decode_pending_dtcs(&[0x47, 0x00]).unwrap().count(), 0);
        assert_eq!(decode_permanent_dtcs(&[0x4A, 0x00]).unwrap().count(), 0);
    }

    #[test]
    fn each_decoder_takes_only_its_own_reply() {
        assert_eq!(
            decode_pending_dtcs(&[0x43, 0x00]).err(),
            Some(Error::WrongService(0x43))
        );
        assert_eq!(
            decode_pending_dtcs(&[0x4A, 0x00]).err(),
            Some(Error::WrongService(0x4A))
        );
        assert_eq!(
            decode_permanent_dtcs(&[0x47, 0x00]).err(),
            Some(Error::WrongService(0x47))
        );
        assert_eq!(
            decode_stored_dtcs(&[0x47, 0x00]).err(),
            Some(Error::WrongService(0x47))
        );
    }

    #[test]
    fn count_must_match_the_codes() {
        for reply in [
            &[0x47, 0x02, 0x04, 0x01][..],
            &[0x47, 0x01, 0x04, 0x01, 0x01, 0x13],
            &[0x47, 0x00, 0x04, 0x01],
            &[0x47, 0x01, 0x04, 0x01, 0xAA],
            &[0x47, 0x01, 0x04],
        ] {
            assert_eq!(decode_pending_dtcs(reply).err(), Some(Error::Malformed));
        }
        assert_eq!(decode_pending_dtcs(&[0x47]).err(), Some(Error::TooShort));
        assert_eq!(
            decode_permanent_dtcs(&[0x4A, 0x01, 0x04]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(decode_permanent_dtcs(&[]).err(), Some(Error::TooShort));
    }

    #[test]
    fn a_refusal_is_a_negative_response() {
        assert_eq!(
            decode_pending_dtcs(&[0x7F, 0x07, 0x12]).err(),
            Some(Error::Negative(NegativeResponse {
                sid: 0x07,
                nrc: Nrc::SubFunctionNotSupported
            }))
        );
        assert_eq!(
            decode_permanent_dtcs(&[0x7F, 0x0A, 0x11]).err(),
            Some(Error::Negative(NegativeResponse {
                sid: 0x0A,
                nrc: Nrc::ServiceNotSupported
            }))
        );
    }
}

mod monitor_status {
    use obdcracker_core::obd::{
        IgnitionType, Monitor, MonitorKind, MonitorStatus, decode_monitor_status,
    };
    use obdcracker_core::response::Error;

    const DONE: Monitor = Monitor {
        supported: true,
        complete: true,
    };
    const NOT_DONE: Monitor = Monitor {
        supported: true,
        complete: false,
    };

    fn status(a: u8, b: u8, c: u8, d: u8) -> MonitorStatus {
        decode_monitor_status(&[0x41, 0x01, a, b, c, d]).unwrap()
    }

    fn supported(status: &MonitorStatus) -> Vec<MonitorKind> {
        status
            .monitors()
            .filter(|(_, monitor)| monitor.supported)
            .map(|(kind, _)| kind)
            .collect()
    }

    #[test]
    fn decodes_the_a7_engines_reply() {
        // The sim's engine answer to 01 01; the A7 is a diesel.
        let status = status(0x00, 0x2F, 0x28, 0x20);
        assert!(!status.mil_on);
        assert_eq!(status.dtc_count, 0);
        assert_eq!(status.ignition, IgnitionType::Compression);
        assert_eq!(status.misfire, DONE);
        assert_eq!(status.fuel_system, NOT_DONE);
        assert_eq!(status.components, DONE);
        assert_eq!(
            supported(&status),
            [
                MonitorKind::Misfire,
                MonitorKind::FuelSystem,
                MonitorKind::Components,
                MonitorKind::BoostPressure,
                MonitorKind::ExhaustGasSensor,
            ]
        );
        assert_eq!(status.monitor(MonitorKind::BoostPressure), Some(DONE));
        assert_eq!(
            status.monitor(MonitorKind::ExhaustGasSensor),
            Some(NOT_DONE)
        );
        assert_eq!(
            status
                .monitor(MonitorKind::ParticulateFilter)
                .map(|m| m.supported),
            Some(false)
        );
    }

    #[test]
    fn mil_and_the_count_share_the_first_byte() {
        let on = status(0xFF, 0, 0, 0);
        assert!(on.mil_on);
        assert_eq!(on.dtc_count, 127);
        let off = status(0x7F, 0, 0, 0);
        assert!(!off.mil_on);
        assert_eq!(off.dtc_count, 127);
        let one = status(0x81, 0, 0, 0);
        assert!(one.mil_on);
        assert_eq!(one.dtc_count, 1);
        let none = status(0x00, 0, 0, 0);
        assert!(!none.mil_on);
        assert_eq!(none.dtc_count, 0);
    }

    #[test]
    fn spark_ignition_names_the_engine_monitors_differently() {
        // Misfire, fuel system and components supported, all complete; every spark monitor supported.
        let status = status(0x00, 0x07, 0xFF, 0x00);
        assert_eq!(status.ignition, IgnitionType::Spark);
        assert_eq!(
            supported(&status),
            [
                MonitorKind::Misfire,
                MonitorKind::FuelSystem,
                MonitorKind::Components,
                MonitorKind::Catalyst,
                MonitorKind::HeatedCatalyst,
                MonitorKind::EvaporativeSystem,
                MonitorKind::SecondaryAir,
                MonitorKind::AcRefrigerant,
                MonitorKind::OxygenSensor,
                MonitorKind::OxygenSensorHeater,
                MonitorKind::EgrVvt,
            ]
        );
        assert_eq!(status.monitor(MonitorKind::Catalyst), Some(DONE));
        assert_eq!(status.monitor(MonitorKind::BoostPressure), None);
        assert_eq!(status.monitor(MonitorKind::ParticulateFilter), None);
    }

    #[test]
    fn compression_ignition_names_every_engine_monitor() {
        let status = status(0x00, 0x08, 0xEB, 0x81);
        assert_eq!(status.ignition, IgnitionType::Compression);
        assert_eq!(
            supported(&status),
            [
                MonitorKind::NmhcCatalyst,
                MonitorKind::NoxScr,
                MonitorKind::BoostPressure,
                MonitorKind::ExhaustGasSensor,
                MonitorKind::ParticulateFilter,
                MonitorKind::EgrVvt,
            ]
        );
        assert_eq!(status.monitor(MonitorKind::NmhcCatalyst), Some(NOT_DONE));
        assert_eq!(status.monitor(MonitorKind::EgrVvt), Some(NOT_DONE));
        assert_eq!(status.monitor(MonitorKind::NoxScr), Some(DONE));
        assert_eq!(status.monitor(MonitorKind::Catalyst), None);
        assert_eq!(status.monitor(MonitorKind::AcRefrigerant), None);
    }

    #[test]
    fn the_common_monitors_read_their_own_bits() {
        // Misfire not supported but incomplete, fuel system supported and incomplete, components
        // supported and complete.
        let status = status(0x00, 0b0011_0110, 0, 0);
        assert_eq!(
            status.misfire,
            Monitor {
                supported: false,
                complete: false
            }
        );
        assert_eq!(status.fuel_system, NOT_DONE);
        assert_eq!(status.components, DONE);
    }

    #[test]
    fn nothing_supported_reports_no_supported_monitors() {
        for ignition_bit in [0x00, 0x08] {
            let status = status(0x00, ignition_bit, 0, 0);
            assert_eq!(supported(&status), Vec::<MonitorKind>::new());
        }
    }

    #[test]
    fn a_complete_bit_on_an_unsupported_monitor_is_reported_not_refused() {
        let status = status(0x00, 0b0111_0000, 0x00, 0xFF);
        assert_eq!(
            status.misfire,
            Monitor {
                supported: false,
                complete: false
            }
        );
        assert_eq!(
            status.monitor(MonitorKind::Catalyst),
            Some(Monitor {
                supported: false,
                complete: false
            })
        );
    }

    #[test]
    fn reserved_bits_are_not_monitors() {
        // Compression ignition bits C2 and C4, and B7, are reserved.
        let status = status(0x00, 0x88, 0x14, 0x14);
        assert_eq!(supported(&status), Vec::<MonitorKind>::new());
    }

    #[test]
    fn the_reply_is_exactly_pid_01_and_four_bytes() {
        assert_eq!(
            decode_monitor_status(&[0x41, 0x01, 0, 0, 0]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_monitor_status(&[0x41, 0x01, 0, 0, 0, 0, 0]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_monitor_status(&[0x41, 0x02, 0, 0, 0, 0]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(decode_monitor_status(&[0x41]).err(), Some(Error::TooShort));
        assert_eq!(decode_monitor_status(&[]).err(), Some(Error::TooShort));
        assert_eq!(
            decode_monitor_status(&[0x43, 0x01, 0, 0, 0, 0]).err(),
            Some(Error::WrongService(0x43))
        );
    }
}

mod freeze_frame {
    use obdcracker_core::obd::{
        Dtc, FreezeFrameValue, SupportedPids, Unit, Value, decode_freeze_frame, freeze_frame,
    };
    use obdcracker_core::response::{Error, NegativeResponse, Nrc};

    #[test]
    fn builds_the_request() {
        assert_eq!(freeze_frame(0x0C, 0), [0x02, 0x0C, 0x00]);
        assert_eq!(freeze_frame(0x02, 0xFF), [0x02, 0x02, 0xFF]);
    }

    #[test]
    fn decodes_a_pid_like_mode_01() {
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x0C, 0x00, 0x1A, 0xF8], 0x0C, 0),
            Ok(FreezeFrameValue::Pid(Value::Quantity {
                value: 1726.0,
                unit: Unit::Rpm
            }))
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x05, 0x02, 0x7B], 0x05, 2),
            Ok(FreezeFrameValue::Pid(Value::Quantity {
                value: 83.0,
                unit: Unit::Celsius
            }))
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x00, 0x00, 0xBE, 0x1F, 0xA8, 0x13], 0x00, 0),
            Ok(FreezeFrameValue::Pid(Value::Supported(SupportedPids::new(
                0x00,
                [0xBE, 0x1F, 0xA8, 0x13]
            ))))
        );
    }

    #[test]
    fn pid_02_is_the_code_that_caused_the_frame() {
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00, 0x01, 0x33], 0x02, 0),
            Ok(FreezeFrameValue::Cause(Some(Dtc::new(0x0133))))
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00, 0x00, 0x00], 0x02, 0),
            Ok(FreezeFrameValue::Cause(None))
        );
    }

    #[test]
    fn pid_02_is_exactly_two_bytes() {
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00, 0x01], 0x02, 0),
            Err(Error::TooShort)
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00], 0x02, 0),
            Err(Error::TooShort)
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00, 0x01, 0x33, 0x00], 0x02, 0),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn an_unknown_pid_keeps_its_bytes() {
        assert_eq!(
            decode_freeze_frame(&[0x42, 0xE1, 0x00, 0x7B, 0x01], 0xE1, 0),
            Ok(FreezeFrameValue::Pid(Value::Raw(&[0x7B, 0x01])))
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0xE1, 0x00], 0xE1, 0),
            Err(Error::TooShort)
        );
    }

    #[test]
    fn a_known_pid_has_exactly_its_length() {
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x0C, 0x00, 0x1A], 0x0C, 0),
            Err(Error::TooShort)
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x0C, 0x00], 0x0C, 0),
            Err(Error::TooShort)
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x0C, 0x00, 0x1A, 0xF8, 0x00], 0x0C, 0),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x05, 0x00, 0x7B, 0x7B], 0x05, 0),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn the_echoed_pid_and_frame_must_be_the_requested_ones() {
        let reply = [0x42, 0x0C, 0x01, 0x1A, 0xF8];
        assert!(decode_freeze_frame(&reply, 0x0C, 1).is_ok());
        assert_eq!(decode_freeze_frame(&reply, 0x0C, 0), Err(Error::Malformed));
        assert_eq!(decode_freeze_frame(&reply, 0x0D, 1), Err(Error::Malformed));
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x02, 0x00, 0x01, 0x33], 0x0C, 0),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn rejects_other_services_refusals_and_empty_replies() {
        assert_eq!(
            decode_freeze_frame(&[0x41, 0x0C, 0x00, 0x1A, 0xF8], 0x0C, 0),
            Err(Error::WrongService(0x41))
        );
        assert_eq!(
            decode_freeze_frame(&[0x7F, 0x02, 0x31], 0x0C, 0),
            Err(Error::Negative(NegativeResponse {
                sid: 0x02,
                nrc: Nrc::RequestOutOfRange
            }))
        );
        assert_eq!(decode_freeze_frame(&[], 0x0C, 0), Err(Error::TooShort));
        assert_eq!(decode_freeze_frame(&[0x42], 0x0C, 0), Err(Error::TooShort));
        assert_eq!(
            decode_freeze_frame(&[0x42, 0x0C], 0x0C, 0),
            Err(Error::TooShort)
        );
    }
}

mod vehicle_info {
    use obdcracker_core::obd::{
        EcuName, check_vin, decode_calids, decode_cvns, decode_ecu_name, decode_supported_info,
        decode_vin, is_vin_placeholder, vehicle_info,
    };
    use obdcracker_core::response::Error;

    fn reply(pid: u8, count: u8, data: &[u8]) -> Vec<u8> {
        let mut reply = vec![0x49, pid, count];
        reply.extend_from_slice(data);
        reply
    }

    fn padded(text: &str, len: usize) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.resize(len, 0);
        bytes
    }

    #[test]
    fn builds_the_request() {
        assert_eq!(vehicle_info(0x02), [0x09, 0x02]);
    }

    #[test]
    fn decodes_the_supported_bitmap() {
        let supported = decode_supported_info(&[0x49, 0x00, 0x54, 0x40, 0x00, 0x00]).unwrap();
        assert_eq!(
            supported.iter().collect::<Vec<_>>(),
            [0x02, 0x04, 0x06, 0x0A]
        );
    }

    #[test]
    fn supported_bitmap_reply_is_exactly_four_bytes() {
        assert_eq!(
            decode_supported_info(&[0x49, 0x00, 0x54, 0x40, 0x00, 0x00, 0xAA]).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_supported_info(&[0x49, 0x00, 0x54, 0x40, 0x00]).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn decodes_the_vin() {
        assert_eq!(
            decode_vin(&reply(0x02, 1, b"1D4GP00R55B123456")),
            Ok("1D4GP00R55B123456")
        );
    }

    #[test]
    fn rejects_a_vin_of_the_wrong_length_or_with_control_bytes() {
        assert_eq!(
            decode_vin(&reply(0x02, 1, b"1D4GP00R55B12345")),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_vin(&reply(0x02, 1, b"1D4GP00R55B12345\x00")),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_vin(&reply(0x02, 2, b"1D4GP00R55B123456")),
            Err(Error::Malformed)
        );
        assert_eq!(
            decode_vin(&reply(0x04, 1, b"1D4GP00R55B123456")),
            Err(Error::Malformed),
            "a CALID reply isn't a VIN reply"
        );
    }

    #[test]
    fn checks_a_vin_from_any_source() {
        assert_eq!(check_vin(b"WAU2MBFC6EN093415"), Ok("WAU2MBFC6EN093415"));
        for bad in [
            &b""[..],
            b"abc",
            b"WAU2MBFC6EN09341",
            b"WAU2MBFC6EN0934155",
            b"WAU2MBFC6EN09341 ",
            b"WAU2MBFC6EN09341\x00",
            b"WAU2MBFC6EN09341I",
            b"wau2mbfc6en093415",
        ] {
            assert_eq!(
                check_vin(bad),
                Err(Error::Malformed),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_vin_placeholder_is_17_of_one_filler_byte() {
        // What a module with no VIN stored sends in F190: the A7's rear lid sends dashes (#63).
        for unset in [[b'-'; 17], [b' '; 17], [0x00; 17], [0xFF; 17]] {
            assert!(is_vin_placeholder(&unset), "{unset:02X?}");
            assert_eq!(check_vin(&unset), Err(Error::Malformed));
        }
        let mut mixed = [b'-'; 17];
        mixed[16] = 0x00;
        for not in [
            &b""[..],
            &[b'-'; 16],
            &[b'-'; 18],
            &mixed,
            &[b'.'; 17],
            &[b'0'; 17],
            b"WAU2MBFC6EN093415",
        ] {
            assert!(!is_vin_placeholder(not), "{not:02X?}");
        }
    }

    #[test]
    fn rejects_characters_a_vin_never_contains() {
        for bad in [
            b"1D4GP00R55B12345I",
            b"1D4GP00R55B12345O",
            b"1D4GP00R55B12345Q",
            b"1d4gp00r55b123456",
        ] {
            assert_eq!(
                decode_vin(&reply(0x02, 1, bad)),
                Err(Error::Malformed),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn decodes_every_calibration_id_without_padding() {
        let mut data = padded("JMB*36761500", 16);
        data.extend(padded("JMB*47872611", 16));
        let reply = reply(0x04, 2, &data);
        let calids: Vec<_> = decode_calids(&reply)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(calids, [Some("JMB*36761500"), Some("JMB*47872611")]);
    }

    #[test]
    fn rejects_calids_that_dont_match_their_count_or_arent_text() {
        assert_eq!(
            decode_calids(&reply(0x04, 2, &padded("JMB*36761500", 16))).err(),
            Some(Error::Malformed)
        );
        let mut data = padded("JMB*36761500", 16);
        data[3] = 0xFF;
        let reply = reply(0x04, 1, &data);
        let first = decode_calids(&reply).unwrap().next();
        assert_eq!(first, Some(Err(Error::Malformed)));
    }

    #[test]
    fn decodes_calibration_verification_numbers_as_hex() {
        let cvns: Vec<_> = decode_cvns(&reply(
            0x06,
            2,
            &[0x17, 0x91, 0xBC, 0x82, 0x00, 0x00, 0x0A, 0xFF],
        ))
        .unwrap()
        .map(|cvn| cvn.to_string())
        .collect();
        assert_eq!(cvns, ["1791BC82", "00000AFF"]);
        assert_eq!(
            decode_cvns(&reply(0x06, 1, &[0x17, 0x91])).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn calid_of_only_padding_is_an_empty_slot() {
        let reply = reply(0x04, 1, &[0; 16]);
        let first = decode_calids(&reply).unwrap().next();
        assert_eq!(first, Some(Ok(None)));
    }

    #[test]
    fn calid_with_padding_before_its_text_is_malformed() {
        let mut data = vec![0; 4];
        data.extend(padded("JMB*36761500", 12));
        let reply = reply(0x04, 1, &data);
        let first = decode_calids(&reply).unwrap().next();
        assert_eq!(first, Some(Err(Error::Malformed)));
    }

    #[test]
    fn decodes_the_a7_engines_five_calids_with_empty_slots() {
        // The 2014 A7 3.0 TDI's engine (7E8), first real-car session (#46): five slots, one of
        // them all 0x00 and paired with CVN 00000000.
        let mut data = b"4G0401N 0016BVAB".to_vec();
        data.extend([0; 16]);
        data.extend(b"0000000000000000");
        data.extend(b"NOX00907807 0015");
        data.extend(b"PMS00906261 4010");
        let reply = reply(0x04, 5, &data);
        let calids: Vec<_> = decode_calids(&reply)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            calids,
            [
                Some("4G0401N 0016BVAB"),
                None,
                Some("0000000000000000"),
                Some("NOX00907807 0015"),
                Some("PMS00906261 4010"),
            ]
        );
    }

    #[test]
    fn calid_and_cvn_replies_carry_at_least_one_item() {
        assert_eq!(
            decode_calids(&reply(0x04, 0, &[])).err(),
            Some(Error::Malformed)
        );
        assert_eq!(
            decode_cvns(&reply(0x06, 0, &[])).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn decodes_the_ecu_name() {
        let mut data = padded("ECM", 4);
        data.push(b'-');
        data.extend(padded("EngineControl", 15));
        assert_eq!(
            decode_ecu_name(&reply(0x0A, 1, &data)),
            Ok(EcuName {
                acronym: "ECM",
                name: "EngineControl"
            })
        );
        assert_eq!(
            decode_ecu_name(&reply(0x0A, 1, &data[..19])),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn ecu_name_has_no_blanks() {
        let mut data = padded("ECM", 4);
        data.push(b'-');
        data.extend(padded("Engine Control", 15));
        assert_eq!(
            decode_ecu_name(&reply(0x0A, 1, &data)),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn ecu_name_of_only_padding_is_malformed() {
        let mut no_acronym = vec![0; 4];
        no_acronym.push(b'-');
        no_acronym.extend(padded("EngineControl", 15));
        let mut no_name = padded("ECM", 4);
        no_name.push(b'-');
        no_name.extend([0; 15]);
        for data in [no_acronym, no_name] {
            assert_eq!(
                decode_ecu_name(&reply(0x0A, 1, &data)),
                Err(Error::Malformed)
            );
        }
    }
}
