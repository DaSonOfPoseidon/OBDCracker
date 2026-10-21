//! The safety policy: allowlist cases and properties that must hold for any input.

use obdcracker_safety::{ModuleIds, NarrowingError, Policy, Protocol, Rejection, Target, Tier};
use proptest::prelude::*;

const ENGINE: Target = Target::Physical(0x7E0);

// Kept separate from the crate's own tables, so a change to the allowlist has to change this too.
const READ_SERVICES: [u8; 7] = [0x01, 0x03, 0x09, 0x10, 0x19, 0x22, 0x3E];
const FLASH_SERVICES: [u8; 7] = [0x11, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3D];
// KWP2000 (ISO 14230-3): ReadStatusOfDTC, ReadDTCByStatus, ReadEcuIdentification,
// ReadDataByLocalIdentifier, TesterPresent.
const KWP2000_READ_SERVICES: [u8; 5] = [0x17, 0x18, 0x1A, 0x21, 0x3E];
// Every read each protocol approves, one example of each form, for the cross-protocol check.
const UDS_READS: &[&[u8]] = &[
    &[0x01, 0x0C],
    &[0x01, 0x0C, 0x0D, 0x05, 0x0F, 0x10, 0x11],
    &[0x03],
    &[0x09, 0x02],
    &[0x10, 0x01],
    &[0x10, 0x03],
    &[0x10, 0x81],
    &[0x10, 0x83],
    &[0x19, 0x02, 0xAF],
    &[0x19, 0x04, 0x00, 0x16, 0xA0, 0xFF],
    &[0x19, 0x0A],
    &[0x22, 0xF1, 0x87],
    &[0x22, 0xF1, 0x87, 0xF1, 0x89, 0xF1, 0x91],
    &[0x3E, 0x00],
    &[0x3E, 0x80],
];
const KWP2000_READS: &[&[u8]] = &[
    &[0x17, 0xFF, 0x00],
    &[0x17, 0xFF],
    &[0x18, 0x02, 0xFF, 0x00],
    &[0x18, 0x02],
    &[0x1A, 0x9B],
    &[0x21, 0x01],
    &[0x3E],
    &[0x3E, 0x01],
    &[0x3E, 0x02],
];
// ECUReset, the routines by local ID and by address, RequestDownload/Upload, TransferData,
// RequestTransferExit, WriteMemoryByAddress.
const KWP2000_FLASH_SERVICES: [u8; 12] = [
    0x11, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3D,
];
// ISO 15765-4: the IDs emissions ECUs answer on (0x7E8..=0x7EF), and the request IDs they listen on.
const OBD_RESPONSE_IDS: [u32; 8] = [0x7E8, 0x7E9, 0x7EA, 0x7EB, 0x7EC, 0x7ED, 0x7EE, 0x7EF];
const OBD_REQUEST_IDS: [u32; 8] = [0x7E0, 0x7E1, 0x7E2, 0x7E3, 0x7E4, 0x7E5, 0x7E6, 0x7E7];

fn approve(target: Target, payload: &[u8]) -> Result<Tier, Rejection> {
    Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .map(|approved| approved.tier())
}

fn approve_kwp2000(target: Target, payload: &[u8]) -> Result<Tier, Rejection> {
    Policy::read_only()
        .approve(Protocol::Kwp2000, target, payload)
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
        .approve(Protocol::Uds, ENGINE, &[0x22, 0xF1, 0x90])
        .unwrap();
    assert_eq!(approved.payload(), &[0x22, 0xF1, 0x90]);
    assert_eq!(approved.target(), ENGINE);
}

#[test]
fn targets_map_to_their_can_ids() {
    assert_eq!(Target::ObdFunctional.can_id(), 0x7DF);
    assert_eq!(ENGINE.can_id(), 0x7E0);
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
    // KWP2000: ClearDiagnosticInformation takes a 2-byte group; the adjustment session,
    // SecurityAccess and the writes by common and by local ID change coding.
    for (payload, tier) in [
        (&[0x14, 0xFF, 0x00][..], Tier::ClearDtc),
        // The group is optional, and its width the manufacturer's.
        (&[0x14], Tier::ClearDtc),
        (&[0x14, 0xFF], Tier::ClearDtc),
        (&[0x2E, 0xF1], Tier::Coding),
        (&[0x3B, 0x01], Tier::Coding),
        (&[0x10, 0x87], Tier::Coding),
        (&[0x27, 0x01], Tier::Coding),
        (&[0x2E, 0xF1, 0x98, 0x00], Tier::Coding),
        (&[0x3B, 0x01, 0x00], Tier::Coding),
    ] {
        assert_eq!(
            approve_kwp2000(ENGINE, payload),
            Err(Rejection::Locked(tier)),
            "{payload:02X?}"
        );
    }
}

#[test]
fn approves_kwp2000_reads_on_a_physical_address() {
    for payload in [
        &[0x1A, 0x9B][..],               // ReadEcuIdentification: VAG's identification
        &[0x21, 0x01],                   // ReadDataByLocalIdentifier
        &[0x18, 0x02, 0xFF, 0x00],       // ReadDTCByStatus: stored DTCs, all groups
        &[0x18, 0x02, 0xFF, 0xFF, 0x00], // the widths are the manufacturer's
        &[0x17, 0xFF, 0x00],             // ReadStatusOfDTC
        &[0x17, 0xFF],
        &[0x3E],       // TesterPresent
        &[0x3E, 0x01], // TesterPresent, response required
    ] {
        assert_eq!(
            approve_kwp2000(ENGINE, payload),
            Ok(Tier::Read),
            "{payload:02X?}"
        );
    }
    let approved = Policy::read_only()
        .approve(Protocol::Kwp2000, ENGINE, &[0x1A, 0x9B])
        .unwrap();
    assert_eq!(approved.protocol(), Protocol::Kwp2000);
    assert_eq!(approved.payload(), &[0x1A, 0x9B]);
}

#[test]
fn kwp2000_parameters_are_read_unmasked() {
    // KWP2000 has no suppress-positive-response bit (#32): 10 85 is its programming session,
    // not UDS's reserved 05, and 10 83 isn't an extended session.
    for (payload, want) in [
        (&[0x10, 0x85][..], Err(Rejection::Banned)), // programming
        (&[0x10, 0x86], Err(Rejection::Banned)),     // development
        (&[0x10, 0x87], Err(Rejection::Locked(Tier::Coding))), // adjustment
        // What a session value means is up to the manufacturer, so none is a read.
        (&[0x10, 0x81], Err(Rejection::NotAllowed)),
        (&[0x10, 0x01], Err(Rejection::NotAllowed)),
        (&[0x10, 0x02], Err(Rejection::NotAllowed)),
        (&[0x10, 0x03], Err(Rejection::NotAllowed)),
        (&[0x10, 0x83], Err(Rejection::NotAllowed)),
        (&[0x10, 0x82], Err(Rejection::NotAllowed)), // periodic transmissions
        // Manufacturer sessions mean different things per make.
        (&[0x10, 0x89], Err(Rejection::NotAllowed)),
        (&[0x10, 0xC0], Err(Rejection::NotAllowed)),
        (&[0x3E, 0x80], Err(Rejection::NotAllowed)),
    ] {
        assert_eq!(approve_kwp2000(ENGINE, payload), want, "{payload:02X?}");
    }
    // The same bytes in UDS, where bit 7 suppresses the reply.
    assert_eq!(approve(ENGINE, &[0x10, 0x83]), Ok(Tier::Read));
    assert_eq!(approve(ENGINE, &[0x3E, 0x80]), Ok(Tier::Read));
    // ECUReset, manufacturer resets (0x80..=0xFF) included.
    for sub in 0..=0xFF {
        assert_eq!(
            approve_kwp2000(ENGINE, &[0x11, sub]),
            Err(Rejection::Banned),
            "{sub:02X}"
        );
    }
}

#[test]
fn rejects_kwp2000_services_that_drive_the_car_or_arent_reads() {
    for payload in [
        &[0x30, 0x01, 0x07, 0x00][..],   // InputOutputControlByLocalIdentifier
        &[0x2F, 0x00, 0x01, 0x03],       // InputOutputControlByCommonIdentifier
        &[0x23, 0x12, 0x00, 0x10, 0x10], // ReadMemoryByAddress
        &[0x28, 0x01],                   // DisableNormalMessageTransmission
        &[0x85, 0x02],                   // ControlDTCSetting
        &[0x83, 0x00],                   // AccessTimingParameters
        &[0x20],                         // StopDiagnosticSession
        &[0x22, 0xF1, 0x90],             // a UDS read is no KWP2000 read
        &[0x19, 0x02, 0xAF],
        &[0x09, 0x02], // OBD-II modes aren't KWP2000
        &[0x01, 0x00],
    ] {
        assert_eq!(
            approve_kwp2000(ENGINE, payload),
            Err(Rejection::NotAllowed),
            "{payload:02X?}"
        );
    }
}

#[test]
fn rejects_malformed_kwp2000_reads() {
    for payload in [
        &[][..],
        &[0x1A],             // no identification option
        &[0x1A, 0x9B, 0x00], // trailing byte
        &[0x21],             // no local ID
        &[0x21, 0x01, 0x02],
        &[0x18],       // no status or group
        &[0x17],       // no group
        &[0x3E, 0x03], // unknown responseRequired
        &[0x3E, 0x01, 0x00],
        &[0x10], // no session
        &[0x10, 0x87, 0x00],
    ] {
        assert!(approve_kwp2000(ENGINE, payload).is_err(), "{payload:02X?}");
    }
}

#[test]
fn every_read_in_one_protocol_is_at_most_a_read_in_the_other() {
    // A module doesn't know which protocol the tester meant.
    for (reads, from, to) in [
        (UDS_READS, Protocol::Uds, Protocol::Kwp2000),
        (KWP2000_READS, Protocol::Kwp2000, Protocol::Uds),
    ] {
        for payload in reads {
            assert_eq!(
                Policy::read_only()
                    .approve(from, ENGINE, payload)
                    .map(|a| a.tier()),
                Ok(Tier::Read),
                "{payload:02X?} as {from:?}"
            );
            let other = Policy::read_only()
                .approve(to, ENGINE, payload)
                .map(|a| a.tier());
            assert!(
                matches!(other, Ok(Tier::Read) | Err(Rejection::NotAllowed)),
                "{payload:02X?} as {to:?}: {other:?}"
            );
        }
    }
}

#[test]
fn kwp2000_follows_the_same_target_rules() {
    assert_eq!(
        approve_kwp2000(Target::ObdFunctional, &[0x1A, 0x9B]),
        Err(Rejection::WrongTarget)
    );
    for id in OBD_RESPONSE_IDS.into_iter().chain([0x6FF, 0x7DF, 0x800]) {
        assert_eq!(
            approve_kwp2000(Target::Physical(id), &[0x1A, 0x9B]),
            Err(Rejection::WrongTarget),
            "{id:X}"
        );
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

#[test]
fn rejects_the_ids_ecus_answer_on() {
    for id in OBD_RESPONSE_IDS {
        for payload in [&[0x22, 0xF1, 0x90][..], &[0x09, 0x02], &[0x3E, 0x00]] {
            assert_eq!(
                approve(Target::Physical(id), payload),
                Err(Rejection::WrongTarget),
                "{id:X}"
            );
        }
    }
}

#[test]
fn approves_reads_on_every_obd_request_id() {
    for id in OBD_REQUEST_IDS {
        assert_eq!(
            approve(Target::Physical(id), &[0x22, 0xF1, 0x90]),
            Ok(Tier::Read),
            "{id:X}"
        );
    }
}

#[test]
fn rejections_work_with_the_question_mark_operator() {
    fn send_flash() -> Result<(), Box<dyn std::error::Error>> {
        Policy::read_only().approve(Protocol::Uds, ENGINE, &[0x10, 0x02])?;
        Ok(())
    }
    assert_eq!(
        send_flash().unwrap_err().to_string(),
        "refused: flash-tier requests are banned"
    );
}

#[test]
fn rejections_say_why() {
    for (rejection, text) in [
        (
            Rejection::Locked(Tier::Coding),
            "refused: the coding tier is locked",
        ),
        (
            Rejection::Locked(Tier::ClearDtc),
            "refused: the clear-DTC tier is locked",
        ),
        (
            Rejection::NotAllowed,
            "refused: not on the allowlist, or malformed",
        ),
        (
            Rejection::WrongTarget,
            "refused: wrong target for this request",
        ),
    ] {
        assert_eq!(rejection.to_string(), text);
    }
}

fn any_target() -> impl Strategy<Value = Target> {
    prop_oneof![
        Just(Target::ObdFunctional),
        any::<u32>().prop_map(Target::Physical),
        (0x700u32..=0x7FF).prop_map(Target::Physical),
        prop::sample::select(&OBD_RESPONSE_IDS[..]).prop_map(Target::Physical),
        any::<u32>().prop_map(Target::Physical29),
        (0x17FC_0000u32..=0x17FE_00FF).prop_map(Target::Physical29),
        (0x18DA_0000u32..=0x18DB_FFFF).prop_map(Target::Physical29),
    ]
}

proptest! {
    #[test]
    fn only_read_services_are_ever_approved(target in any_target(), payload in prop::collection::vec(any::<u8>(), 0..16)) {
        if let Ok(approved) = Policy::read_only().approve(Protocol::Uds, target, &payload) {
            prop_assert_eq!(approved.tier(), Tier::Read);
            prop_assert_eq!(approved.protocol(), Protocol::Uds);
            prop_assert!(READ_SERVICES.contains(&payload[0]));
            prop_assert_eq!(approved.payload(), &payload[..]);
            prop_assert!(!OBD_RESPONSE_IDS.contains(&approved.target().can_id()));
        }
    }

    #[test]
    fn flash_services_are_banned_everywhere(target in any_target(), sid in prop::sample::select(&FLASH_SERVICES[..]), rest in prop::collection::vec(any::<u8>(), 0..16)) {
        let mut payload = vec![sid];
        payload.extend(rest);
        let result = Policy::read_only().approve(Protocol::Uds, target, &payload);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }

    #[test]
    fn only_kwp2000_reads_are_ever_approved(target in any_target(), payload in prop::collection::vec(any::<u8>(), 0..16)) {
        if let Ok(approved) = Policy::read_only().approve(Protocol::Kwp2000, target, &payload) {
            prop_assert_eq!(approved.tier(), Tier::Read);
            prop_assert_eq!(approved.protocol(), Protocol::Kwp2000);
            prop_assert!(KWP2000_READ_SERVICES.contains(&payload[0]));
            prop_assert_eq!(approved.payload(), &payload[..]);
            prop_assert!(!OBD_RESPONSE_IDS.contains(&approved.target().can_id()));
        }
    }

    #[test]
    fn kwp2000_flash_services_are_banned_everywhere(target in any_target(), sid in prop::sample::select(&KWP2000_FLASH_SERVICES[..]), rest in prop::collection::vec(any::<u8>(), 0..16)) {
        let mut payload = vec![sid];
        payload.extend(rest);
        let result = Policy::read_only().approve(Protocol::Kwp2000, target, &payload);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }

    #[test]
    fn kwp2000_programming_and_development_sessions_are_banned_everywhere(target in any_target(), session in prop::sample::select(&[0x85u8, 0x86][..])) {
        let result = Policy::read_only().approve(Protocol::Kwp2000, target, &[0x10, session]);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }

    #[test]
    fn a_read_in_one_protocol_is_never_locked_or_banned_in_the_other(
        sid in prop::sample::select([&READ_SERVICES[..], &KWP2000_READ_SERVICES[..]].concat()),
        data in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        // A module doesn't know which protocol the tester meant.
        let mut payload = vec![sid];
        payload.extend(data);
        for (from, to) in [(Protocol::Uds, Protocol::Kwp2000), (Protocol::Kwp2000, Protocol::Uds)] {
            if Policy::read_only().approve(from, ENGINE, &payload).is_ok() {
                let other = Policy::read_only().approve(to, ENGINE, &payload);
                prop_assert!(
                    matches!(other.map(|a| a.tier()), Ok(Tier::Read) | Err(Rejection::NotAllowed)),
                    "{:02X?} as {:?}", payload, to
                );
            }
        }
    }

    #[test]
    fn programming_session_is_banned_everywhere(target in any_target(), suppress in any::<bool>()) {
        let sub = if suppress { 0x82 } else { 0x02 };
        let result = Policy::read_only().approve(Protocol::Uds, target, &[0x10, sub]);
        prop_assert_eq!(result.map(|a| a.tier()), Err(Rejection::Banned));
    }
}

// The A7's modules (#49): engine, transmission, gateway, instruments.
const A7: [ModuleIds; 4] = [
    ModuleIds {
        request: 0x7E0,
        reply: 0x7E8,
    },
    ModuleIds {
        request: 0x7E1,
        reply: 0x7E9,
    },
    ModuleIds {
        request: 0x710,
        reply: 0x77A,
    },
    ModuleIds {
        request: 0x714,
        reply: 0x77E,
    },
];

fn a7() -> Policy {
    Policy::read_only().narrowed_to(&A7).unwrap()
}

#[test]
fn a_narrowed_policy_accepts_only_its_modules_request_ids() {
    let read = [0x22, 0xF1, 0x87];
    for module in A7 {
        let approved = a7()
            .approve(Protocol::Uds, Target::Physical(module.request), &read)
            .unwrap();
        assert_eq!(approved.reply_id(), Some(module.reply));
        // A request on a reply ID would look like that module's answer to everyone listening.
        assert_eq!(
            a7().approve(Protocol::Uds, Target::Physical(module.reply), &read),
            Err(Rejection::WrongTarget)
        );
    }
    // In the bare policy's range, but not a module of this car.
    for id in [0x700, 0x711, 0x7E2, 0x7A0] {
        assert_eq!(
            a7().approve(Protocol::Uds, Target::Physical(id), &read),
            Err(Rejection::WrongTarget),
            "{id:03X}"
        );
    }
    // The OBD-II broadcast isn't a module, and is unaffected.
    let vin = a7()
        .approve(Protocol::Uds, Target::ObdFunctional, &[0x09, 0x02])
        .unwrap();
    assert_eq!(vin.reply_id(), None);
}

#[test]
fn reply_ids_are_known_for_obd_ids_or_from_a_profile() {
    let read = [0x22, 0xF1, 0x87];
    // ISO 15765-4: an OBD-II ECU answers on its request ID + 8.
    for (request, reply) in OBD_REQUEST_IDS.iter().zip(OBD_RESPONSE_IDS) {
        let approved = Policy::read_only()
            .approve(Protocol::Uds, Target::Physical(*request), &read)
            .unwrap();
        assert_eq!(approved.reply_id(), Some(reply));
    }
    // Without a profile, any other module's reply ID is unknown.
    let approved = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical(0x710), &read)
        .unwrap();
    assert_eq!(approved.reply_id(), None);
}

#[test]
fn narrowing_refuses_inconsistent_modules() {
    let ids = |request, reply| ModuleIds { request, reply };
    for (modules, error) in [
        // A request ID the bare policy refuses.
        (vec![ids(0x7E8, 0x7F0)], NarrowingError::Request(0x7E8)),
        (vec![ids(0x6FF, 0x769)], NarrowingError::Request(0x6FF)),
        (vec![ids(0x7DF, 0x7E7)], NarrowingError::Request(0x7DF)),
        // A reply ID outside 0x700..=0x7FF, or the broadcast ID.
        (vec![ids(0x710, 0x800)], NarrowingError::Reply(0x800)),
        (vec![ids(0x710, 0x7DF)], NarrowingError::Reply(0x7DF)),
        // One module's request ID is another's reply ID.
        (
            vec![ids(0x710, 0x77A), ids(0x77A, 0x7E4)],
            NarrowingError::RequestIsReply(0x77A),
        ),
        (
            vec![ids(0x710, 0x710)],
            NarrowingError::RequestIsReply(0x710),
        ),
        // One request ID, two reply IDs.
        (
            vec![ids(0x710, 0x77A), ids(0x710, 0x77B)],
            NarrowingError::AmbiguousReply(0x710),
        ),
    ] {
        assert_eq!(
            Policy::read_only().narrowed_to(&modules).err(),
            Some(error),
            "{modules:?}"
        );
    }
    // Modules sharing a request and reply ID (extended addressing, such as Toyota's 0x750) are
    // one target.
    let shared = [ids(0x750, 0x758), ids(0x750, 0x758)];
    assert!(Policy::read_only().narrowed_to(&shared).is_ok());
    assert!(
        NarrowingError::RequestIsReply(0x77A)
            .to_string()
            .contains("77A")
    );
}

fn any_id() -> impl Strategy<Value = u32> {
    prop_oneof![
        0x6F0u32..=0x80F,
        0x17FB_FF00u32..=0x17FE_01FF,
        0x18DA_F000u32..=0x18DA_F2FF,
        (0u32..=0xFF).prop_map(|ta| 0x18DA_00F1 | (ta << 8)),
    ]
}

fn any_modules() -> impl Strategy<Value = Vec<ModuleIds>> {
    prop::collection::vec(
        (any_id(), any_id()).prop_map(|(request, reply)| ModuleIds { request, reply }),
        0..6,
    )
}

proptest! {
    #[test]
    fn narrowing_never_widens_the_policy(
        modules in any_modules(),
        target in any_target(),
        protocol in prop::sample::select(&[Protocol::Uds, Protocol::Kwp2000][..]),
        payload in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let Ok(narrowed) = Policy::read_only().narrowed_to(&modules) else {
            return Ok(());
        };
        if let Ok(approved) = narrowed.approve(protocol, target, &payload) {
            prop_assert!(Policy::read_only().approve(protocol, target, &payload).is_ok());
            if let Target::Physical(id) | Target::Physical29(id) = target {
                prop_assert!(modules.iter().any(|m| m.request == id));
                prop_assert!(!modules.iter().any(|m| m.reply == id));
            }
            prop_assert_eq!(approved.payload(), &payload[..]);
        }
    }
}

// VAG's 29-bit diagnostic IDs: requests on 0x17FC00xx, replies on 0x17FE00xx.
const VAG29_REQUEST: u32 = 0x17FC_0076;
const VAG29_REPLY: u32 = 0x17FE_0076;

#[test]
fn approves_reads_on_29_bit_physical_ids() {
    for id in [
        VAG29_REQUEST,
        0x17FC_0000,
        0x17FC_00FF,
        // ISO 15765-4 normal fixed addressing: 0x18DA, the module, the tester (F1).
        0x18DA_10F1,
        0x18DA_00F1,
        0x18DA_FFF1,
    ] {
        assert_eq!(
            approve(Target::Physical29(id), &[0x22, 0xF1, 0x87]),
            Ok(Tier::Read),
            "{id:08X}"
        );
        assert_eq!(
            approve_kwp2000(Target::Physical29(id), &[0x1A, 0x9B]),
            Ok(Tier::Read),
            "{id:08X}"
        );
    }
    assert_eq!(Target::Physical29(VAG29_REQUEST).can_id(), VAG29_REQUEST);
    assert!(Target::Physical29(VAG29_REQUEST).is_29_bit());
    assert!(!ENGINE.is_29_bit());
    assert!(!Target::ObdFunctional.is_29_bit());
}

#[test]
fn rejects_29_bit_ids_outside_the_diagnostic_ranges_and_reply_ids() {
    for id in [
        VAG29_REPLY, // VAG's reply IDs
        0x17FE_0000,
        0x17FC_0100, // past VAG's request range
        0x17FB_FFFF,
        0x18DA_F110, // ISO replies: to the tester
        0x18DA_F1F1, // the tester to itself
        0x18DA_10F2, // another tester's
        0x18DB_33F1, // the 29-bit OBD-II broadcast
        0x1FFF_FFFF,
        0x2000_0000, // more than 29 bits
        0x0000_07E0, // an 11-bit ID can't be sent as 29-bit
        0x0000_0710,
        0,
    ] {
        assert_eq!(
            approve(Target::Physical29(id), &[0x22, 0xF1, 0x87]),
            Err(Rejection::WrongTarget),
            "{id:08X}"
        );
    }
    // Nor can a 29-bit ID be sent as 11-bit.
    assert_eq!(
        approve(Target::Physical(VAG29_REQUEST), &[0x22, 0xF1, 0x87]),
        Err(Rejection::WrongTarget)
    );
    // OBD-II modes go to the 11-bit broadcast or emissions ECUs only.
    assert_eq!(
        approve(Target::Physical29(0x18DA_10F1), &[0x09, 0x02]),
        Ok(Tier::Read)
    );
}

#[test]
fn iso_29_bit_reply_ids_are_known_and_vag_ones_come_from_a_profile() {
    let read = [0x22, 0xF1, 0x87];
    let approved = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical29(0x18DA_10F1), &read)
        .unwrap();
    assert_eq!(approved.reply_id(), Some(0x18DA_F110));
    let approved = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical29(VAG29_REQUEST), &read)
        .unwrap();
    assert_eq!(approved.reply_id(), None);
    let narrowed = Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: VAG29_REQUEST,
            reply: VAG29_REPLY,
        }])
        .unwrap();
    let approved = narrowed
        .approve(Protocol::Uds, Target::Physical29(VAG29_REQUEST), &read)
        .unwrap();
    assert_eq!(approved.reply_id(), Some(VAG29_REPLY));
    // The narrowed policy refuses the 11-bit IDs it wasn't narrowed to, and the 29-bit request ID
    // as 11-bit.
    for target in [Target::Physical(0x710), Target::Physical(VAG29_REQUEST)] {
        assert_eq!(
            narrowed.approve(Protocol::Uds, target, &read),
            Err(Rejection::WrongTarget)
        );
    }
}

#[test]
fn narrowing_refuses_29_bit_pairs_of_mixed_width_or_on_the_wrong_ranges() {
    let ids = |request, reply| ModuleIds { request, reply };
    for (modules, error) in [
        // A request on a reply range.
        (
            vec![ids(VAG29_REPLY, VAG29_REQUEST)],
            NarrowingError::Request(VAG29_REPLY),
        ),
        // A 29-bit request with an 11-bit reply, and the other way round.
        (
            vec![ids(VAG29_REQUEST, 0x77A)],
            NarrowingError::Reply(0x77A),
        ),
        (
            vec![ids(0x710, VAG29_REPLY)],
            NarrowingError::Reply(VAG29_REPLY),
        ),
        // A 29-bit reply that's no reply ID: a request ID, the broadcast, more than 29 bits.
        (
            vec![ids(VAG29_REQUEST, 0x17FC_0077)],
            NarrowingError::Reply(0x17FC_0077),
        ),
        (
            vec![ids(VAG29_REQUEST, 0x18DB_33F1)],
            NarrowingError::Reply(0x18DB_33F1),
        ),
        (
            vec![ids(VAG29_REQUEST, 0x2000_0000)],
            NarrowingError::Reply(0x2000_0000),
        ),
    ] {
        assert_eq!(
            Policy::read_only().narrowed_to(&modules).err(),
            Some(error),
            "{modules:X?}"
        );
    }
    assert!(
        Policy::read_only()
            .narrowed_to(&[
                ids(VAG29_REQUEST, VAG29_REPLY),
                ids(0x18DA_10F1, 0x18DA_F110),
                ids(0x710, 0x77A)
            ])
            .is_ok()
    );
}
