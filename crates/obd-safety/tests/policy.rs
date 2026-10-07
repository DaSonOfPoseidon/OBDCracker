use obd_safety::{Policy, Rejection, Target, Tier};
use proptest::prelude::*;

const ENGINE: Target = Target::Physical(0x7E0);

// Kept separate from the crate's own tables, so a change to the allowlist has to change this too.
const READ_SERVICES: [u8; 7] = [0x01, 0x03, 0x09, 0x10, 0x19, 0x22, 0x3E];
const FLASH_SERVICES: [u8; 7] = [0x11, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3D];

fn approve(target: Target, payload: &[u8]) -> Result<Tier, Rejection> {
    Policy::read_only()
        .approve(target, payload)
        .map(|approved| approved.tier())
}

#[test]
fn approves_obd_reads_on_the_functional_address() {
    // Mode 01 PID 0C (RPM), mode 03 (stored DTCs), mode 09 PID 02 (VIN)
    for payload in [&[0x01, 0x0C][..], &[0x03], &[0x09, 0x02]] {
        assert_eq!(approve(Target::ObdFunctional, payload), Ok(Tier::Read));
    }
}

#[test]
fn approves_uds_reads_on_a_physical_address() {
    for payload in [
        &[0x22, 0xF1, 0x90][..], // ReadDataByIdentifier: VIN
        &[0x22, 0xF1, 0x87, 0xF1, 0x89],
        &[0x19, 0x02, 0xFF], // ReadDTCInformation by status mask
        &[0x3E, 0x00],       // TesterPresent
        &[0x3E, 0x80],       // TesterPresent, suppress response
        &[0x10, 0x01],       // DefaultSession
        &[0x10, 0x03],       // ExtendedSession
        &[0x10, 0x83],       // ExtendedSession, suppress response
    ] {
        assert_eq!(approve(ENGINE, payload), Ok(Tier::Read), "{payload:02X?}");
    }
}

#[test]
fn approved_request_carries_its_payload_and_target_unchanged() {
    let approved = Policy::read_only()
        .approve(ENGINE, &[0x22, 0xF1, 0x90])
        .unwrap();
    assert_eq!(approved.payload(), &[0x22, 0xF1, 0x90]);
    assert_eq!(approved.target(), ENGINE);
}

#[test]
fn locks_clear_dtc_and_coding_in_read_only() {
    for (payload, tier) in [
        (&[0x04][..], Tier::ClearDtc),
        (&[0x14, 0xFF, 0xFF, 0xFF], Tier::ClearDtc),
        (&[0x2E, 0xF1, 0x98, 0x00], Tier::Coding),
        (&[0x27, 0x03], Tier::Coding),
    ] {
        assert_eq!(approve(ENGINE, payload), Err(Rejection::Locked(tier)));
    }
}

#[test]
fn bans_programming_session_and_every_flash_service() {
    assert_eq!(approve(ENGINE, &[0x10, 0x02]), Err(Rejection::Banned));
    assert_eq!(approve(ENGINE, &[0x10, 0x82]), Err(Rejection::Banned));
    // RequestDownload of 0x100 bytes at 0x0
    assert_eq!(
        approve(ENGINE, &[0x34, 0x00, 0x44, 0, 0, 0, 0, 0, 0, 1, 0]),
        Err(Rejection::Banned)
    );
}

#[test]
fn rejects_services_that_silence_or_drive_the_car() {
    for payload in [
        &[0x28, 0x03, 0x01][..],         // CommunicationControl: disable rx and tx
        &[0x85, 0x02],                   // ControlDTCSetting off
        &[0x2F, 0x00, 0x01, 0x03, 0x01], // IO control
        &[0x08, 0x01],                   // OBD mode 08: control on-board component
        &[0x23, 0x12, 0x00, 0x10],       // ReadMemoryByAddress
    ] {
        assert_eq!(
            approve(ENGINE, payload),
            Err(Rejection::NotAllowed),
            "{payload:02X?}"
        );
    }
}

#[test]
fn rejects_malformed_reads() {
    for payload in [
        &[][..],
        &[0x22],                      // no DID
        &[0x22, 0xF1],                // half a DID
        &[0x01],                      // mode 01 with no PID
        &[0x01, 1, 2, 3, 4, 5, 6, 7], // more than six PIDs
        &[0x03, 0x00],                // mode 03 takes no data
        &[0x09],                      // mode 09 with no PID
        &[0x10, 0x03, 0x00],          // trailing byte
        &[0x3E, 0x01],                // unknown subfunction
        &[0x10, 0x60],                // unknown session
        &[0x19],                      // no subfunction
    ] {
        assert!(approve(ENGINE, payload).is_err(), "{payload:02X?}");
    }
}

#[test]
fn rejects_uds_on_the_functional_address() {
    assert_eq!(
        approve(Target::ObdFunctional, &[0x22, 0xF1, 0x90]),
        Err(Rejection::WrongTarget)
    );
}

#[test]
fn rejects_physical_ids_outside_the_diagnostic_range() {
    for id in [0x000, 0x123, 0x6FF, 0x7DF, 0x800, 0x1FFF_FFFF] {
        assert_eq!(
            approve(Target::Physical(id), &[0x22, 0xF1, 0x90]),
            Err(Rejection::WrongTarget),
            "{id:X}"
        );
    }
}

fn any_target() -> impl Strategy<Value = Target> {
    prop_oneof![
        Just(Target::ObdFunctional),
        any::<u32>().prop_map(Target::Physical),
        (0x700u32..=0x7FF).prop_map(Target::Physical),
    ]
}

proptest! {
    #[test]
    fn only_read_services_are_ever_approved(target in any_target(), payload in prop::collection::vec(any::<u8>(), 0..16)) {
        if let Ok(approved) = Policy::read_only().approve(target, &payload) {
            prop_assert_eq!(approved.tier(), Tier::Read);
            prop_assert!(READ_SERVICES.contains(&payload[0]));
            prop_assert_eq!(approved.payload(), &payload[..]);
        }
    }

    #[test]
    fn flash_services_are_banned_everywhere(target in any_target(), sid in prop::sample::select(&FLASH_SERVICES[..]), rest in prop::collection::vec(any::<u8>(), 0..16)) {
        let mut payload = vec![sid];
        payload.extend(rest);
        let result = Policy::read_only().approve(target, &payload);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }

    #[test]
    fn programming_session_is_banned_everywhere(target in any_target(), suppress in any::<bool>()) {
        let sub = if suppress { 0x82 } else { 0x02 };
        let result = Policy::read_only().approve(target, &[0x10, sub]);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }
}
