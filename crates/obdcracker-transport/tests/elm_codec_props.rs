//! The ELM codec on arbitrary adapter output: it never panics, stays bounded, and round-trips
//! every frame it can print.

use obdcracker_transport::elm::codec::{Event, Line, LineSplitter, MAX_LINE, parse_line};
use obdcracker_transport::hex;
use proptest::prelude::*;

// Whatever a line parses as, a frame is always a valid classic CAN frame.
fn check(line: &Line) -> Result<(), TestCaseError> {
    if let Line::Frame(frame) = line {
        prop_assert!(frame.id() <= 0x7FF);
        prop_assert!((1..=8).contains(&frame.data().len()));
    }
    Ok(())
}

proptest! {
    #[test]
    fn any_output_splits_into_bounded_lines(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 0..20)
    ) {
        let mut splitter = LineSplitter::default();
        let mut events = Vec::new();
        for chunk in &chunks {
            splitter.push(chunk, &mut events);
        }
        for event in &events {
            if let Event::Line(line) = event {
                // Lossy UTF-8 can turn one byte into three, but never more.
                prop_assert!(!line.is_empty() && line.len() <= MAX_LINE * 3);
                prop_assert!(!line.contains(['\r', '\n', '>', '\0']));
                check(&parse_line(line))?;
            }
        }
    }

    #[test]
    fn splitting_doesnt_depend_on_how_reads_are_chunked(
        bytes in prop::collection::vec(any::<u8>(), 0..300),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut whole = Vec::new();
        LineSplitter::default().push(&bytes, &mut whole);
        let (a, b) = bytes.split_at(cut.index(bytes.len() + 1));
        let mut parts = Vec::new();
        let mut splitter = LineSplitter::default();
        splitter.push(a, &mut parts);
        splitter.push(b, &mut parts);
        prop_assert_eq!(whole, parts);
    }

    #[test]
    fn any_text_parses_without_panicking(text in ".{0,120}") {
        check(&parse_line(&text))?;
    }

    #[test]
    fn every_printed_frame_round_trips(
        id in 0u32..=0x7FF,
        data in prop::collection::vec(any::<u8>(), 1..=8),
    ) {
        let line = format!("{id:03X} {}", hex(&data));
        let Line::Frame(frame) = parse_line(&line) else {
            return Err(TestCaseError::fail(format!("{line:?} isn't a frame")));
        };
        prop_assert_eq!(frame.id(), id);
        prop_assert_eq!(frame.data(), &data[..]);
    }
}
