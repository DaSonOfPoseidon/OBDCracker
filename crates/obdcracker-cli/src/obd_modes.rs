//! What `scan` prints for each ECU past its PIDs, mode 09 and stored DTCs: the MIL and readiness
//! monitors, pending and permanent DTCs, the freeze frame and the mode 06 monitor IDs
//! (`docs/usage.md#scan`).

use obdcracker_core::obd::{MonitorKind, MonitorStatus};
use obdcracker_transport::fingerprint::ReadError;
use obdcracker_transport::hex;
use obdcracker_transport::scan::{FreezeFrame, ObdEcu, PidValue};

// One line per fact, each starting with the ECU's CAN ID.
pub(crate) fn lines(ecu: &ObdEcu) -> Vec<String> {
    let id = ecu.source;
    let mut out = Vec::new();
    match &ecu.monitor_status {
        Some(Ok(status)) => readiness(&mut out, id, status),
        Some(Err(e)) => out.push(format!("{id:03X} readiness ({e})")),
        None => {}
    }
    if let Some(read) = &ecu.pending_dtcs {
        out.push(dtc_line(id, "pending", read, None));
    }
    if let Some(read) = &ecu.permanent_dtcs {
        // Mode 0A was added to J1979 after the first OBD-II ECUs, which ignore it.
        let older = matches!(read, Err(ReadError::NoReply))
            .then_some("older ECUs ignore mode 0A")
            .filter(|_| matches!(ecu.pending_dtcs, Some(Ok(_))));
        out.push(dtc_line(id, "permanent", read, older));
    }
    match &ecu.freeze_frame {
        Some(Ok(frame)) => freeze_frame(&mut out, id, frame),
        Some(Err(e)) => out.push(format!("{id:03X} freeze frame {}", failed(e))),
        None => {}
    }
    match (&ecu.monitor_ids, &ecu.monitor_ids_cut_short) {
        (Some(Ok(ids)), cut) => {
            let ids: Vec<_> = ids.iter().map(|mid| format!("{mid:02X}")).collect();
            out.push(if ids.is_empty() {
                format!("{id:03X} mode 06 monitor IDs (none)")
            } else {
                format!("{id:03X} mode 06 monitor IDs {}", ids.join(", "))
            });
            if let Some((page, e)) = cut {
                out.push(format!(
                    "{id:03X} mode 06 monitor IDs from {page:02X} on not read ({e})"
                ));
            }
        }
        (Some(Err(e)), _) => out.push(format!("{id:03X} mode 06 monitor IDs {}", failed(e))),
        (None, _) => {}
    }
    out
}

// `(not supported)` where the ECU said it doesn't have the mode, otherwise why the read failed.
fn failed(e: &ReadError) -> String {
    if e.is_not_supported() {
        "(not supported)".to_owned()
    } else {
        format!("({e})")
    }
}

fn dtc_line(
    id: u32,
    which: &str,
    read: &Result<Vec<obdcracker_core::obd::Dtc>, ReadError>,
    hint: Option<&str>,
) -> String {
    match read {
        Ok(dtcs) if dtcs.is_empty() => format!("{id:03X} {which} DTCs (none)"),
        Ok(dtcs) => {
            let dtcs: Vec<_> = dtcs.iter().map(ToString::to_string).collect();
            format!("{id:03X} {which} DTCs {}", dtcs.join(", "))
        }
        Err(e) => match hint {
            Some(hint) => format!("{id:03X} {which} DTCs ({e}; {hint})"),
            None => format!("{id:03X} {which} DTCs {}", failed(e)),
        },
    }
}

// The three monitors every engine has run continuously; the rest run when the car's conditions
// allow, so "incomplete" can just mean the drive cycle hasn't happened (SAE J1979).
fn is_continuous(kind: MonitorKind) -> bool {
    matches!(
        kind,
        MonitorKind::Misfire | MonitorKind::FuelSystem | MonitorKind::Components
    )
}

fn readiness(out: &mut Vec<String>, id: u32, status: &MonitorStatus) {
    let count = status.dtc_count;
    out.push(format!(
        "{id:03X} MIL {}, {count} DTC{}, {} ignition",
        if status.mil_on { "on" } else { "off" },
        if count == 1 { "" } else { "s" },
        match status.ignition {
            obdcracker_core::obd::IgnitionType::Spark => "spark",
            obdcracker_core::obd::IgnitionType::Compression => "compression",
        }
    ));
    for (kind, monitor) in status.monitors().filter(|(_, monitor)| monitor.supported) {
        out.push(format!(
            "{id:03X} monitor {} {}{}",
            kind.name().replace('_', " "),
            if monitor.complete {
                "complete"
            } else {
                "incomplete"
            },
            if is_continuous(kind) {
                " (continuous)"
            } else {
                ""
            }
        ));
    }
}

fn freeze_frame(out: &mut Vec<String>, id: u32, frame: &FreezeFrame) {
    let Some(cause) = frame.cause else {
        out.push(format!("{id:03X} freeze frame (none)"));
        return;
    };
    out.push(format!("{id:03X} freeze frame stored by {cause}"));
    match &frame.pids {
        Ok(pids) => {
            for (pid, value) in pids {
                out.push(match value {
                    Ok(PidValue::Quantity { value, unit }) => {
                        // A count has no unit, so no trailing space either.
                        format!("{id:03X} freeze frame PID {pid:02X} {value} {unit}")
                            .trim_end()
                            .to_owned()
                    }
                    Ok(PidValue::Raw(bytes)) => {
                        format!("{id:03X} freeze frame PID {pid:02X} [{}]", hex(bytes))
                    }
                    Err(e) => format!("{id:03X} freeze frame PID {pid:02X} ({e})"),
                });
            }
        }
        Err(e) => out.push(format!("{id:03X} freeze frame PIDs ({e})")),
    }
    if let Some((page, e)) = &frame.pids_cut_short {
        out.push(format!(
            "{id:03X} freeze frame PIDs from {page:02X} on not read ({e})"
        ));
    }
}

#[cfg(test)]
mod tests {
    use obdcracker_core::obd::{Dtc, MonitorStatus, Unit, decode_monitor_status};
    use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
    use obdcracker_transport::fingerprint::ReadError;
    use obdcracker_transport::scan::{FreezeFrame, ObdEcu, PidValue};

    use super::lines;

    // An ECU that said nothing of the later modes.
    fn silent_ecu() -> ObdEcu {
        ObdEcu {
            source: 0x7E8,
            pids: Ok(vec![]),
            pids_cut_short: None,
            supported_info: Ok(vec![]),
            ecu_name: Ok(String::new()),
            stored_dtcs: Ok(vec![]),
            monitor_status: None,
            pending_dtcs: None,
            permanent_dtcs: None,
            freeze_frame: None,
            monitor_ids: None,
            monitor_ids_cut_short: None,
        }
    }

    fn not_supported(sid: u8) -> ReadError {
        ReadError::Reply(ReplyError::Negative(NegativeResponse {
            sid,
            nrc: Nrc::ServiceNotSupported,
        }))
    }

    fn status(a: u8, b: u8, c: u8, d: u8) -> MonitorStatus {
        decode_monitor_status(&[0x41, 0x01, a, b, c, d]).unwrap()
    }

    #[test]
    fn a_document_from_before_the_reads_prints_nothing() {
        assert_eq!(lines(&silent_ecu()), Vec::<String>::new());
    }

    #[test]
    fn the_a7_engines_readiness_lists_each_supported_monitor_and_marks_the_continuous_ones() {
        // Session 11's `41 01 00 2F 28 20`: diesel; misfire and components complete, fuel system
        // incomplete; boost pressure complete, exhaust gas sensor incomplete.
        let ecu = ObdEcu {
            monitor_status: Some(Ok(status(0x00, 0x2F, 0x28, 0x20))),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            [
                "7E8 MIL off, 0 DTCs, compression ignition",
                "7E8 monitor misfire complete (continuous)",
                "7E8 monitor fuel system incomplete (continuous)",
                "7E8 monitor components complete (continuous)",
                "7E8 monitor boost pressure complete",
                "7E8 monitor exhaust gas sensor incomplete",
            ]
        );
    }

    #[test]
    fn the_transmissions_status_has_the_three_common_monitors_only() {
        // `41 01 00 04 00 00`: B bit 2, so only the component monitor is supported.
        let ecu = ObdEcu {
            source: 0x7E9,
            monitor_status: Some(Ok(status(0x00, 0x04, 0x00, 0x00))),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            [
                "7E9 MIL off, 0 DTCs, spark ignition",
                "7E9 monitor components complete (continuous)",
            ]
        );
    }

    #[test]
    fn the_mil_and_a_single_dtc_are_worded_for_their_count() {
        let ecu = ObdEcu {
            monitor_status: Some(Ok(status(0x81, 0x00, 0x00, 0x00))),
            ..silent_ecu()
        };
        assert_eq!(lines(&ecu), ["7E8 MIL on, 1 DTC, spark ignition"]);
    }

    #[test]
    fn a_status_that_failed_says_why() {
        let ecu = ObdEcu {
            monitor_status: Some(Err(ReadError::NoReply)),
            ..silent_ecu()
        };
        assert_eq!(lines(&ecu), ["7E8 readiness (no reply)"]);
    }

    #[test]
    fn pending_and_permanent_dtcs_are_listed_none_unsupported_or_failed() {
        let ecu = ObdEcu {
            pending_dtcs: Some(Ok(vec![Dtc::new(0x0299), Dtc::new(0xFFFF)])),
            permanent_dtcs: Some(Ok(vec![])),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            ["7E8 pending DTCs P0299, U3FFF", "7E8 permanent DTCs (none)"]
        );
        let ecu = ObdEcu {
            pending_dtcs: Some(Err(ReadError::NoReply)),
            permanent_dtcs: Some(Err(not_supported(0x0A))),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            [
                "7E8 pending DTCs (no reply)",
                "7E8 permanent DTCs (not supported)"
            ]
        );
    }

    #[test]
    fn silence_on_mode_0a_after_an_answered_mode_07_is_called_what_it_probably_is() {
        let ecu = ObdEcu {
            pending_dtcs: Some(Ok(vec![])),
            permanent_dtcs: Some(Err(ReadError::NoReply)),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu)[1],
            "7E8 permanent DTCs (no reply; older ECUs ignore mode 0A)"
        );
    }

    #[test]
    fn a_freeze_frame_shows_its_cause_then_each_value() {
        let ecu = ObdEcu {
            freeze_frame: Some(Ok(FreezeFrame {
                cause: Some(Dtc::new(0x0299)),
                pids: Ok(vec![
                    (
                        0x05,
                        Ok(PidValue::Quantity {
                            value: 90.0,
                            unit: Unit::Celsius,
                        }),
                    ),
                    (
                        0x30,
                        Ok(PidValue::Quantity {
                            value: 4.0,
                            unit: Unit::Count,
                        }),
                    ),
                    (0x1C, Ok(PidValue::Raw(vec![0x06]))),
                    (0x0C, Err(ReadError::NoReply)),
                ]),
                pids_cut_short: Some((0x20, ReadError::NoReply)),
            })),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            [
                "7E8 freeze frame stored by P0299",
                "7E8 freeze frame PID 05 90 °C",
                "7E8 freeze frame PID 30 4",
                "7E8 freeze frame PID 1C [06]",
                "7E8 freeze frame PID 0C (no reply)",
                "7E8 freeze frame PIDs from 20 on not read (no reply)",
            ]
        );
    }

    #[test]
    fn an_empty_frame_is_none_and_a_refused_one_is_not_supported() {
        let none = ObdEcu {
            freeze_frame: Some(Ok(FreezeFrame {
                cause: None,
                pids: Ok(vec![]),
                pids_cut_short: None,
            })),
            ..silent_ecu()
        };
        assert_eq!(lines(&none), ["7E8 freeze frame (none)"]);
        let refused = ObdEcu {
            freeze_frame: Some(Err(not_supported(0x02))),
            ..silent_ecu()
        };
        assert_eq!(lines(&refused), ["7E8 freeze frame (not supported)"]);
        let no_pids = ObdEcu {
            freeze_frame: Some(Ok(FreezeFrame {
                cause: Some(Dtc::new(0x0299)),
                pids: Err(ReadError::NoReply),
                pids_cut_short: None,
            })),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&no_pids),
            [
                "7E8 freeze frame stored by P0299",
                "7E8 freeze frame PIDs (no reply)"
            ]
        );
    }

    #[test]
    fn monitor_ids_are_listed_with_where_the_list_was_cut() {
        let ecu = ObdEcu {
            monitor_ids: Some(Ok(vec![0x01, 0x21])),
            monitor_ids_cut_short: Some((0x40, ReadError::NoReply)),
            ..silent_ecu()
        };
        assert_eq!(
            lines(&ecu),
            [
                "7E8 mode 06 monitor IDs 01, 21",
                "7E8 mode 06 monitor IDs from 40 on not read (no reply)"
            ]
        );
        let none = ObdEcu {
            monitor_ids: Some(Ok(vec![])),
            ..silent_ecu()
        };
        assert_eq!(lines(&none), ["7E8 mode 06 monitor IDs (none)"]);
        let refused = ObdEcu {
            monitor_ids: Some(Err(not_supported(0x06))),
            ..silent_ecu()
        };
        assert_eq!(lines(&refused), ["7E8 mode 06 monitor IDs (not supported)"]);
    }
}
