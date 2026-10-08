//! Reading what an ELM327 prints: splitting its output into lines and classifying each one.
//! Examples follow the ELM327 datasheet (ELM327DS v2.0), with headers and spaces on.

use obdcracker_transport::elm::codec::{
    CanFrame, Event, Line, LineSplitter, MAX_LINE, Status, parse_line,
};

fn split(chunks: &[&[u8]]) -> Vec<Event> {
    let mut splitter = LineSplitter::default();
    let mut events = Vec::new();
    for chunk in chunks {
        splitter.push(chunk, &mut events);
    }
    events
}

fn line(text: &str) -> Event {
    Event::Line(text.to_owned())
}

fn frame(line: &str) -> CanFrame {
    match parse_line(line) {
        Line::Frame(frame) => frame,
        other => panic!("{line:?} parsed as {other:?}"),
    }
}

mod splitter {
    use super::*;

    #[test]
    fn splits_lines_and_reports_the_prompt() {
        assert_eq!(
            split(&[b"7E8 03 41 0D 32 AA AA AA AA\r\r>"]),
            [line("7E8 03 41 0D 32 AA AA AA AA"), Event::Prompt]
        );
    }

    #[test]
    fn joins_a_line_and_prompt_split_across_reads() {
        assert_eq!(
            split(&[b"7E8 03 4", b"1 0D 32\r", b"\r", b">"]),
            [line("7E8 03 41 0D 32"), Event::Prompt]
        );
    }

    #[test]
    fn accepts_linefeeds_and_skips_empty_lines() {
        assert_eq!(
            split(&[b"\r\n\r\nOK\r\n\r\n>"]),
            [line("OK"), Event::Prompt]
        );
    }

    // The datasheet warns that the ELM327's UART may insert stray NUL bytes.
    #[test]
    fn drops_nul_bytes() {
        assert_eq!(split(&[b"O\0K\r\0>"]), [line("OK"), Event::Prompt]);
    }

    #[test]
    fn a_prompt_ends_an_unterminated_line() {
        assert_eq!(split(&[b"OK>"]), [line("OK"), Event::Prompt]);
    }

    #[test]
    fn an_overlong_line_is_reported_once_and_not_kept() {
        let long = vec![b'A'; MAX_LINE + 1];
        assert_eq!(
            split(&[&long, &long, b"\rOK\r>"]),
            [Event::Overlong, line("OK"), Event::Prompt]
        );
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_kept() {
        let exact = "A".repeat(MAX_LINE);
        assert_eq!(
            split(&[exact.as_bytes(), b"\r"]),
            [Event::Line(exact.clone())]
        );
    }

    // Adapter text ends up on the user's terminal, so it must not carry escape sequences or
    // other control characters (anyone in range of a Wi-Fi adapter can send them).
    #[test]
    fn replaces_everything_but_printable_ascii() {
        assert_eq!(
            split(&[b"\x1B[2J\x07ELM\x7F\xE2\x80\xAE\tv1\r"]),
            [line(
                "\u{FFFD}[2J\u{FFFD}ELM\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}v1"
            )]
        );
    }
}

mod frames {
    use super::*;

    #[test]
    fn parses_a_single_frame_with_its_header() {
        let f = frame("7E8 06 41 00 BE 3F A8 13");
        assert_eq!(f.id(), 0x7E8);
        assert_eq!(f.data(), [0x06, 0x41, 0x00, 0xBE, 0x3F, 0xA8, 0x13]);
    }

    // The datasheet's mode 09 PID 04 example from two ECUs, interleaved.
    #[test]
    fn parses_first_and_consecutive_frames() {
        let first = frame("7E8 10 13 49 04 01 35 36 30");
        assert_eq!(first.id(), 0x7E8);
        assert_eq!(first.data()[..2], [0x10, 0x13]);
        assert_eq!(frame("7E9 22 00 00 00 00 00 00 00").id(), 0x7E9);
    }

    #[test]
    fn takes_one_to_eight_data_bytes() {
        assert_eq!(frame("7E8 01").data(), [0x01]);
        assert_eq!(frame("7E8 01 02 03 04 05 06 07 08").data().len(), 8);
        assert!(matches!(
            parse_line("7E8 01 02 03 04 05 06 07 08 09"),
            Line::Text(_)
        ));
        assert!(matches!(parse_line("7E8"), Line::Text(_)));
    }

    // ELM327s (and the independent ELM327-emulator) print a space after every byte, the last
    // one included.
    #[test]
    fn accepts_one_trailing_space() {
        assert_eq!(frame("7E8 03 41 0D 32 ").data(), [0x03, 0x41, 0x0D, 0x32]);
    }

    #[test]
    fn accepts_lower_case_hex() {
        assert_eq!(frame("7e8 03 41 0d 32").data(), [0x03, 0x41, 0x0D, 0x32]);
    }

    #[test]
    fn the_header_is_an_11_bit_id() {
        assert_eq!(frame("000 01").id(), 0);
        assert_eq!(frame("7FF 01").id(), 0x7FF);
        assert!(matches!(parse_line("800 01"), Line::Text(_)));
        assert!(matches!(parse_line("7E 01"), Line::Text(_)));
        assert!(matches!(parse_line("07E8 01"), Line::Text(_)));
    }

    #[test]
    fn rejects_malformed_bytes() {
        for text in [
            "7E8 1", "7E8 012", "7E8 +1", "+E8 01", "7E8 0G", "7E8  01", "7E8 01  ", " 7E8 01",
            "7E801", "7E8\t01",
        ] {
            assert!(matches!(parse_line(text), Line::Text(_)), "{text:?}");
        }
    }

    #[test]
    fn a_frame_with_an_error_marker_is_an_error() {
        assert_eq!(
            parse_line("7E8 10 14 49 02 01 31 44 34 <DATA ERROR"),
            Line::Status(Status::DataError)
        );
        assert_eq!(
            parse_line("7E8 10 14 49 02 <RX ERROR"),
            Line::Status(Status::RxError)
        );
    }
}

mod statuses {
    use super::*;

    #[test]
    fn recognises_every_datasheet_message() {
        for (text, status) in [
            ("?", Status::Unknown),
            ("NO DATA", Status::NoData),
            ("SEARCHING...", Status::Searching),
            ("STOPPED", Status::Stopped),
            ("BUFFER FULL", Status::BufferFull),
            ("BUS BUSY", Status::BusBusy),
            ("BUS ERROR", Status::BusError),
            ("CAN ERROR", Status::CanError),
            ("DATA ERROR", Status::DataError),
            ("FB ERROR", Status::FbError),
            ("LV RESET", Status::LvReset),
            ("UNABLE TO CONNECT", Status::UnableToConnect),
            ("ACT ALERT", Status::ActAlert),
            ("!ACT ALERT", Status::ActAlert),
            ("LP ALERT", Status::LpAlert),
            ("!LP ALERT", Status::LpAlert),
            ("ERR94", Status::Internal(0x94)),
            ("ERR01", Status::Internal(0x01)),
        ] {
            assert_eq!(parse_line(text), Line::Status(status), "{text:?}");
        }
    }

    #[test]
    fn ok_is_its_own_line() {
        assert_eq!(parse_line("OK"), Line::Ok);
    }

    #[test]
    fn anything_else_is_text() {
        for text in [
            "ELM327 v2.0",
            "12.3V",
            "ATE0",
            "ERR",
            "ERR9",
            "ERR941",
            "ERR+9",
            "NO DATA!",
        ] {
            assert_eq!(parse_line(text), Line::Text(text.to_owned()), "{text:?}");
        }
    }

    #[test]
    fn some_statuses_mean_the_adapter_lost_its_settings() {
        for status in [Status::LvReset, Status::LpAlert, Status::Internal(0x94)] {
            assert!(status.loses_settings() && status.is_failure(), "{status}");
        }
        for status in [
            Status::NoData,
            Status::CanError,
            Status::BusError,
            Status::Unknown,
        ] {
            assert!(!status.loses_settings(), "{status}");
        }
    }

    #[test]
    fn only_errors_are_failures() {
        assert!(!Status::NoData.is_failure());
        assert!(!Status::Searching.is_failure());
        assert!(!Status::Stopped.is_failure());
        assert!(Status::CanError.is_failure());
        assert!(Status::Unknown.is_failure());
        assert!(Status::Internal(0x94).is_failure());
    }
}
