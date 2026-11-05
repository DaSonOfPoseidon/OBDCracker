//! Which device is opened, and what is shown of it.

use nusb::ErrorKind;

use super::nusb_usb::open_error_text;
use super::select::{DeviceSummary, KNOWN, Unchosen, choose, printable};

fn device(serial: Option<&str>) -> DeviceSummary {
    DeviceSummary::new(0x1209, 0x2323, serial, Some("candleLight"))
}

#[test]
fn only_known_gs_usb_devices_are_on_the_list() {
    assert!(KNOWN.contains(&(0x1D50, 0x606F)));
    assert!(KNOWN.contains(&(0x1209, 0x2323)));
    // An OBDLink EX (FTDI) and a random hub aren't.
    assert!(!KNOWN.contains(&(0x0403, 0x6015)));
    assert!(!KNOWN.contains(&(0x1D6B, 0x0002)));
    let mut sorted = KNOWN.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), KNOWN.len(), "no duplicates");
}

#[test]
fn no_device_is_not_found() {
    assert_eq!(choose::<u8>(vec![], None), Err(Unchosen::None));
    assert_eq!(choose::<u8>(vec![], Some("A1")), Err(Unchosen::None));
}

#[test]
fn the_only_device_is_chosen_with_or_without_a_serial() {
    assert_eq!(choose(vec![(device(Some("A1")), 7)], None), Ok(7));
    assert_eq!(choose(vec![(device(Some("A1")), 7)], Some("A1")), Ok(7));
    assert_eq!(choose(vec![(device(None), 7)], None), Ok(7));
}

#[test]
fn a_serial_that_matches_nothing_is_refused_not_guessed() {
    assert_eq!(
        choose(vec![(device(Some("A1")), 7)], Some("A2")),
        Err(Unchosen::NoSuchSerial)
    );
    // A device with no serial can't be picked by one.
    assert_eq!(
        choose(vec![(device(None), 7)], Some("A1")),
        Err(Unchosen::NoSuchSerial)
    );
    // Serials are exact.
    assert_eq!(
        choose(vec![(device(Some("A1")), 7)], Some("a1")),
        Err(Unchosen::NoSuchSerial)
    );
    assert_eq!(
        choose(vec![(device(Some("A1")), 7)], Some("")),
        Err(Unchosen::NoSuchSerial)
    );
}

#[test]
fn several_devices_with_no_serial_are_listed_and_none_is_chosen() {
    let candidates = vec![(device(Some("A1")), 1), (device(Some("B2")), 2)];
    match choose(candidates, None) {
        Err(Unchosen::Many(list)) => {
            let serials: Vec<_> = list.iter().map(|d| d.serial.clone().unwrap()).collect();
            assert_eq!(serials, ["A1", "B2"]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_serial_picks_one_of_several() {
    let candidates = vec![(device(Some("A1")), 1), (device(Some("B2")), 2)];
    assert_eq!(choose(candidates, Some("B2")), Ok(2));
}

#[test]
fn two_devices_with_the_same_serial_are_still_ambiguous() {
    let candidates = vec![(device(Some("A1")), 1), (device(Some("A1")), 2)];
    assert!(matches!(
        choose(candidates, Some("A1")),
        Err(Unchosen::Many(list)) if list.len() == 2
    ));
}

#[test]
fn what_a_device_wrote_cannot_reach_a_terminal_as_an_escape() {
    assert_eq!(printable("ABC 123"), "ABC 123");
    assert_eq!(printable("a\x1b[2Jb"), "a?[2Jb");
    assert_eq!(printable("a\nb\r\t\0c"), "a?b???c");
    assert_eq!(printable("caf\u{e9}"), "caf?");
    assert_eq!(printable(&"x".repeat(500)).len(), 64);
    let shown = DeviceSummary::new(0x1209, 0x2323, Some("S\x1b]0;x\x07"), Some("P\x1b[31m"));
    let text = shown.to_string();
    assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text:?}");
    assert!(
        text.starts_with("1209:2323 P?[31m (serial S?]0;x?)"),
        "{text}"
    );
}

#[test]
fn a_serial_given_as_shown_selects_the_device() {
    // A serial with a control character can be picked by typing what is shown.
    let candidates = vec![(device(Some("S\x01")), 1), (device(Some("T")), 2)];
    assert_eq!(choose(candidates, Some("S?")), Ok(1));
}

#[test]
fn a_missing_serial_is_shown_as_such() {
    assert_eq!(
        device(None).to_string(),
        "1209:2323 candleLight (no serial number)"
    );
}

#[test]
fn a_device_a_kernel_driver_holds_points_to_socketcan() {
    let text = open_error_text(ErrorKind::Busy, "busy");
    assert!(text.contains("--socketcan"), "{text}");
    assert!(text.contains("never detaches"), "{text}");
    assert!(open_error_text(ErrorKind::PermissionDenied, "x").contains("udev"));
    assert!(open_error_text(ErrorKind::NotFound, "x").contains("WinUSB"));
    assert!(open_error_text(ErrorKind::Disconnected, "x").contains("unplugged"));
}
