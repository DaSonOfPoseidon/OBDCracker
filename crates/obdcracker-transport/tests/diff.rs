//! Comparing two reads of the same car: what each kind of change is reported as, in what order, and
//! that a failed read is never reported as every entry having gone.

use obdcracker_core::obd::Unit;
use obdcracker_core::obd::{Cvn, Dtc, MonitorKind, MonitorStatus, decode_monitor_status};
use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_core::uds::{DtcCount, DtcFormat, DtcRecord, DtcStatus, UdsDtc};
use obdcracker_transport::diff::{self, Change, DuplicateError, Input, List, ModuleId, Scope};
use obdcracker_transport::fingerprint::{
    Calibration, DidValue, Fingerprint, Identification, ReadError, UdsModule,
};
use obdcracker_transport::read_dids::DidsData;
use obdcracker_transport::scan::{FreezeFrame, ModuleScan, ObdEcu, PidValue, Scan};
use obdcracker_transport::sweep::Sweep;
use proptest::prelude::*;

type Did = (u16, Result<DidValue, ReadError>);

// The comparisons of inputs that repeat nothing, which is what most tests are about.
fn diff_fingerprint(old: &Fingerprint, new: &Fingerprint) -> Vec<Change> {
    diff::diff_fingerprint(old, new).unwrap()
}

fn diff_scan(old: &Scan, new: &Scan) -> Vec<Change> {
    diff::diff_scan(old, new).unwrap()
}

fn diff_sweep(
    module: &UdsModule,
    old: &Sweep,
    new: &Sweep,
    range: std::ops::RangeInclusive<u16>,
) -> Vec<Change> {
    diff::diff_sweep(module, old, new, range).unwrap()
}

fn diff_dids_data(
    module: &UdsModule,
    old: &Result<DidsData, ReadError>,
    new: &Result<DidsData, ReadError>,
) -> Vec<Change> {
    diff::diff_dids_data(module, old, new).unwrap()
}

fn diff_vins(old: &[(u32, String)], new: &[(u32, String)]) -> Vec<Change> {
    diff::diff_vins(old, new).unwrap()
}

fn calibration(source: u32, calids: &[Option<&str>], cvns: &[[u8; 4]]) -> Calibration {
    Calibration {
        source,
        calids: Ok(calids
            .iter()
            .map(|calid| calid.map(str::to_owned))
            .collect()),
        cvns: Ok(cvns.iter().map(|&cvn| Cvn(cvn)).collect()),
    }
}

fn text(did: u16, value: &str) -> Did {
    (did, Ok(DidValue::Text(value.to_owned())))
}

fn identification(name: &str, response_id: u32, dids: Vec<Did>) -> Identification {
    Identification {
        name: name.to_owned(),
        response_id,
        dids,
    }
}

fn fingerprint(ecus: Vec<Calibration>, modules: Vec<Identification>) -> Fingerprint {
    Fingerprint { ecus, modules }
}

fn module_id(name: &str, response_id: u32) -> ModuleId {
    ModuleId {
        name: name.to_owned(),
        response_id,
    }
}

fn lines(changes: &[Change]) -> Vec<String> {
    changes.iter().map(ToString::to_string).collect()
}

fn engine_calibrations(calid: &str, cvn: [u8; 4]) -> Fingerprint {
    fingerprint(vec![calibration(0x7E8, &[Some(calid)], &[cvn])], Vec::new())
}

// ---- fingerprints ---------------------------------------------------------------------------

#[test]
fn identical_fingerprints_have_no_changes() {
    let one = fingerprint(
        vec![calibration(
            0x7E8,
            &[Some("4G0907589F"), None],
            &[[1, 2, 3, 4], [0; 4]],
        )],
        vec![identification(
            "transmission",
            0x7E9,
            vec![
                text(0xF189, "0005"),
                (0xF18C, Err(ReadError::NoReply)),
                (0xF190, Ok(DidValue::NotSet)),
            ],
        )],
    );
    assert_eq!(diff_fingerprint(&one, &one.clone()), []);
    let empty = fingerprint(Vec::new(), Vec::new());
    assert_eq!(diff_fingerprint(&empty, &empty), []);
}

#[test]
fn a_changed_calibration_id_and_cvn_are_reported_by_slot() {
    let old = engine_calibrations("4G0907589F", [0x9B, 0xF7, 0x47, 0x0D]);
    let new = engine_calibrations("4G0907589G", [0x38, 0xD3, 0xFF, 0x82]);
    let changes = diff_fingerprint(&old, &new);
    assert_eq!(
        changes,
        [
            Change::CalidChanged {
                source: 0x7E8,
                slot: 1,
                old: Some("4G0907589F".to_owned()),
                new: Some("4G0907589G".to_owned()),
            },
            Change::CvnChanged {
                source: 0x7E8,
                slot: 1,
                old: Cvn([0x9B, 0xF7, 0x47, 0x0D]),
                new: Cvn([0x38, 0xD3, 0xFF, 0x82]),
            },
        ]
    );
    assert_eq!(
        lines(&changes),
        [
            "7E8 CALID 1: \"4G0907589F\" → \"4G0907589G\"",
            "7E8 CVN 1: 9BF7470D → 38D3FF82",
        ]
    );
}

#[test]
fn an_empty_calibration_slot_is_a_value_and_slots_past_the_end_are_added_or_removed() {
    let old = fingerprint(
        vec![calibration(0x7E8, &[Some("A"), None], &[[1; 4], [0; 4]])],
        Vec::new(),
    );
    let new = fingerprint(
        vec![calibration(
            0x7E8,
            &[None, None, Some("C")],
            &[[1; 4], [0; 4], [3; 4]],
        )],
        Vec::new(),
    );
    let changes = diff_fingerprint(&old, &new);
    assert_eq!(
        lines(&changes),
        [
            "7E8 CALID 1: \"A\" → (empty)",
            "7E8 CALID 3 added: \"C\"",
            "7E8 CVN 3 added: 03030303",
        ]
    );
    let back = diff_fingerprint(&new, &old);
    assert_eq!(
        lines(&back),
        [
            "7E8 CALID 1: (empty) → \"A\"",
            "7E8 CALID 3 removed: \"C\"",
            "7E8 CVN 3 removed: 03030303",
        ]
    );
    assert_eq!(
        back[1],
        Change::CalidRemoved {
            source: 0x7E8,
            slot: 3,
            calid: Some("C".to_owned())
        }
    );
}

#[test]
fn an_ecu_that_appears_or_disappears_is_one_change() {
    let none = fingerprint(Vec::new(), Vec::new());
    let one = engine_calibrations("A", [1; 4]);
    assert_eq!(
        diff_fingerprint(&none, &one),
        [Change::EcuAdded { source: 0x7E8 }]
    );
    assert_eq!(lines(&diff_fingerprint(&one, &none)), ["7E8 ECU removed"]);
    // The 29-bit form keeps its 8 digits
    let wide = fingerprint(vec![calibration(0x17FE_0010, &[], &[])], Vec::new());
    assert_eq!(
        lines(&diff_fingerprint(&none, &wide)),
        ["17FE0010 ECU added"]
    );
}

#[test]
fn a_calibration_list_that_failed_is_one_change_not_every_entry() {
    let read = engine_calibrations("A", [1; 4]);
    let mut failed = read.clone();
    failed.ecus[0].calids = Err(ReadError::NoReply);
    failed.ecus[0].cvns = Err(ReadError::CountMismatch { calids: 2, cvns: 1 });
    let changes = diff_fingerprint(&read, &failed);
    assert_eq!(
        changes,
        [
            Change::Unreadable {
                scope: Scope::Ecu { source: 0x7E8 },
                list: List::Calids,
                old: None,
                new: Some(ReadError::NoReply),
            },
            Change::Unreadable {
                scope: Scope::Ecu { source: 0x7E8 },
                list: List::Cvns,
                old: None,
                new: Some(ReadError::CountMismatch { calids: 2, cvns: 1 }),
            },
        ]
    );
    assert_eq!(
        lines(&changes),
        [
            "7E8 CALIDs can't be compared: old read, new no reply",
            "7E8 CVNs can't be compared: old read, new 1 CVNs for 2 calibration IDs",
        ]
    );
    // Failing the same way on both sides is no change; failing differently is one
    assert_eq!(diff_fingerprint(&failed, &failed.clone()), []);
    let mut other = failed.clone();
    other.ecus[0].calids = Err(ReadError::StillPending);
    assert_eq!(
        diff_fingerprint(&failed, &other),
        [Change::Unreadable {
            scope: Scope::Ecu { source: 0x7E8 },
            list: List::Calids,
            old: Some(ReadError::NoReply),
            new: Some(ReadError::StillPending),
        }]
    );
}

#[test]
fn a_changed_did_shows_both_values_and_a_did_on_one_side_only_is_absent_on_the_other() {
    let old = fingerprint(
        Vec::new(),
        vec![identification(
            "transmission",
            0x7E9,
            vec![
                text(0xF189, "0005"),
                text(0xF191, "same"),
                (0xF18C, Err(ReadError::NoReply)),
                (0xF1AA, Ok(DidValue::Bytes(vec![0x1A, 0x2A]))),
            ],
        )],
    );
    let new = fingerprint(
        Vec::new(),
        vec![identification(
            "transmission",
            0x7E9,
            vec![
                text(0xF189, "0006"),
                text(0xF191, "same"),
                text(0xF18C, "serial"),
                (0xF19E, Ok(DidValue::NotSet)),
            ],
        )],
    );
    let changes = diff_fingerprint(&old, &new);
    assert_eq!(
        lines(&changes),
        [
            "transmission F189 \"0005\" → \"0006\"",
            "transmission F18C (no reply) → \"serial\"",
            "transmission F19E (absent) → (not set)",
            "transmission F1AA [1A 2A] → (absent)",
        ]
    );
    assert_eq!(
        changes[0],
        Change::DidChanged {
            module: module_id("transmission", 0x7E9),
            did: 0xF189,
            old: Some(Ok(DidValue::Text("0005".to_owned()))),
            new: Some(Ok(DidValue::Text("0006".to_owned()))),
        }
    );
}

#[test]
fn a_did_that_failed_differently_is_a_change_and_one_that_failed_the_same_way_is_not() {
    let refused = |nrc: u8| {
        ReadError::Reply(ReplyError::Negative(
            obdcracker_core::response::NegativeResponse {
                sid: 0x22,
                nrc: nrc.into(),
            },
        ))
    };
    let with = |error: ReadError| {
        fingerprint(
            Vec::new(),
            vec![identification("engine", 0x7E8, vec![(0xF187, Err(error))])],
        )
    };
    assert_eq!(
        diff_fingerprint(&with(refused(0x31)), &with(refused(0x31))),
        []
    );
    let changes = diff_fingerprint(&with(refused(0x31)), &with(refused(0x22)));
    assert_eq!(changes.len(), 1);
    assert!(matches!(
        &changes[0],
        Change::DidChanged { did: 0xF187, .. }
    ));
}

#[test]
fn a_module_that_appears_or_disappears_is_one_change_and_a_new_response_id_is_both() {
    let none = fingerprint(Vec::new(), Vec::new());
    let mmi = fingerprint(
        Vec::new(),
        vec![identification("5F mmi", 0x77F, vec![text(0xF187, "x")])],
    );
    let changes = diff_fingerprint(&none, &mmi);
    assert_eq!(
        changes,
        [Change::ModuleAdded {
            module: module_id("5F mmi", 0x77F)
        }]
    );
    assert_eq!(lines(&changes), ["module added: 5F mmi (0x77F)"]);
    assert_eq!(
        lines(&diff_fingerprint(&mmi, &none)),
        ["module removed: 5F mmi (0x77F)"]
    );

    let moved = fingerprint(
        Vec::new(),
        vec![identification("5F mmi", 0x77E, vec![text(0xF187, "y")])],
    );
    assert_eq!(
        lines(&diff_fingerprint(&mmi, &moved)),
        [
            "module added: 5F mmi (0x77E)",
            "module removed: 5F mmi (0x77F)",
        ]
    );
}

#[test]
fn changes_come_in_a_fixed_order_whatever_order_the_lists_were_in() {
    let ecu = |source: u32, calid: &str| calibration(source, &[Some(calid)], &[[1; 4]]);
    let module = |name: &str, id: u32, value: &str| {
        identification(name, id, vec![text(0xF189, value), text(0xF187, value)])
    };
    let old = fingerprint(
        vec![ecu(0x7E9, "a"), ecu(0x7E8, "a")],
        vec![module("b", 0x7E9, "1"), module("a", 0x7E8, "1")],
    );
    let new = fingerprint(
        vec![ecu(0x7E8, "b"), ecu(0x7E9, "b")],
        vec![module("a", 0x7E8, "2"), module("b", 0x7E9, "2")],
    );
    let expected = [
        "7E8 CALID 1: \"a\" → \"b\"",
        "7E9 CALID 1: \"a\" → \"b\"",
        "a F187 \"1\" → \"2\"",
        "a F189 \"1\" → \"2\"",
        "b F187 \"1\" → \"2\"",
        "b F189 \"1\" → \"2\"",
    ];
    assert_eq!(lines(&diff_fingerprint(&old, &new)), expected);
    let mut flipped = new.clone();
    flipped.ecus.reverse();
    flipped.modules.reverse();
    flipped.modules.iter_mut().for_each(|m| m.dids.reverse());
    assert_eq!(lines(&diff_fingerprint(&old, &flipped)), expected);
}

#[test]
fn a_hand_edited_fingerprint_that_repeats_something_is_refused() {
    let engine = |dids: Vec<Did>| identification("engine", 0x7E8, dids);
    let clean = fingerprint(
        vec![calibration(0x7E8, &[Some("a")], &[[1; 4]])],
        vec![engine(vec![text(0xF189, "0005")])],
    );
    let refused =
        |old: &Fingerprint, new: &Fingerprint| diff::diff_fingerprint(old, new).unwrap_err();
    // The same ECU, module or DID twice, with the same value or a conflicting one
    let ecu_twice = fingerprint(
        vec![
            calibration(0x7E8, &[Some("a")], &[[1; 4]]),
            calibration(0x7E8, &[Some("b")], &[[1; 4]]),
        ],
        Vec::new(),
    );
    let module_twice = fingerprint(
        Vec::new(),
        vec![engine(vec![text(0xF189, "0006")]), engine(Vec::new())],
    );
    let did_twice = fingerprint(
        Vec::new(),
        vec![engine(vec![text(0xF189, "0006"), text(0xF189, "0005")])],
    );
    let did_twice_alike = fingerprint(
        Vec::new(),
        vec![engine(vec![text(0xF189, "0005"), text(0xF189, "0005")])],
    );
    for (bad, entry) in [
        (&ecu_twice, "ECU 7E8"),
        (&module_twice, "module engine (0x7E8)"),
        (&did_twice, "DID F189 of engine (0x7E8)"),
        (&did_twice_alike, "DID F189 of engine (0x7E8)"),
    ] {
        let expected = |input| DuplicateError {
            input,
            entry: entry.to_owned(),
        };
        assert_eq!(refused(bad, &clean), expected(Input::Old), "{entry}");
        assert_eq!(refused(&clean, bad), expected(Input::New), "{entry}");
        assert_eq!(refused(bad, bad), expected(Input::Old), "{entry}");
    }
    // The old F189 was 0005 and the new one lists 0006 and then 0005: not "no changes"
    let error = refused(&clean, &did_twice);
    assert_eq!(
        error.to_string(),
        "the new result lists DID F189 of engine (0x7E8) twice"
    );
    // Different modules or ECUs that merely look alike aren't repeats
    let alike = fingerprint(
        vec![
            calibration(0x7E8, &[Some("a")], &[[1; 4]]),
            calibration(0x7E9, &[Some("a")], &[[1; 4]]),
        ],
        vec![
            engine(vec![text(0xF189, "1"), text(0xF18C, "1")]),
            identification("engine", 0x7E9, vec![text(0xF189, "1")]),
            identification("transmission", 0x7E8, vec![text(0xF189, "1")]),
        ],
    );
    assert_eq!(diff_fingerprint(&alike, &alike), []);
}

#[test]
fn a_repeated_text_in_an_error_is_made_printable() {
    let named = |name: &str| fingerprint(Vec::new(), vec![identification(name, 0x7E8, Vec::new())]);
    let twice = fingerprint(
        Vec::new(),
        vec![
            identification("a\u{1b}[31m", 0x7E8, Vec::new()),
            identification("a\u{1b}[31m", 0x7E8, Vec::new()),
        ],
    );
    let error = diff::diff_fingerprint(&named("x"), &twice).unwrap_err();
    assert!(
        error.entry.chars().all(|c| (' '..='~').contains(&c)),
        "{error}"
    );
}

// ---- scans ----------------------------------------------------------------------------------

fn obd_ecu(source: u32) -> ObdEcu {
    ObdEcu {
        source,
        pids: Ok(vec![
            (
                0x05,
                Ok(PidValue::Quantity {
                    value: 63.0,
                    unit: Unit::Celsius,
                }),
            ),
            (0x0C, Ok(PidValue::Raw(vec![1, 2]))),
        ]),
        pids_cut_short: None,
        supported_info: Ok(vec![0x02, 0x04]),
        ecu_name: Ok("ECM-EngineControl".to_owned()),
        stored_dtcs: Ok(vec![Dtc::new(0x0401)]),
        monitor_status: Some(Ok(status(0x00, 0x2F, 0x28, 0x20))),
        pending_dtcs: Some(Ok(vec![])),
        permanent_dtcs: Some(Ok(vec![])),
        freeze_frame: Some(Ok(FreezeFrame {
            cause: None,
            pids: Ok(vec![]),
            pids_cut_short: None,
        })),
        monitor_ids: Some(Ok(vec![0x01, 0x02])),
        monitor_ids_cut_short: None,
    }
}

fn status(a: u8, b: u8, c: u8, d: u8) -> MonitorStatus {
    decode_monitor_status(&[0x41, 0x01, a, b, c, d]).unwrap()
}

fn module_scan(name: &str, response_id: u32) -> ModuleScan {
    ModuleScan {
        name: name.to_owned(),
        response_id,
        dids: vec![text(0xF187, "part")],
        dtc_count: Ok(DtcCount {
            availability: DtcStatus(0xFF),
            format: DtcFormat::Iso14229,
            count: 1,
        }),
        dtcs: Ok(vec![DtcRecord {
            dtc: UdsDtc::new(0x16A0),
            status: DtcStatus(0x08),
        }]),
        answered: true,
    }
}

fn scan(ecus: Vec<ObdEcu>, modules: Vec<ModuleScan>) -> Scan {
    Scan { ecus, modules }
}

#[test]
fn identical_scans_have_no_changes_and_live_values_are_not_compared() {
    let old = scan(vec![obd_ecu(0x7E8)], vec![module_scan("engine", 0x7E8)]);
    assert_eq!(diff_scan(&old, &old.clone()), []);
    let mut running = old.clone();
    running.ecus[0].pids = Ok(vec![
        (
            0x05,
            Ok(PidValue::Quantity {
                value: 91.0,
                unit: Unit::Celsius,
            }),
        ),
        (0x0C, Ok(PidValue::Raw(vec![9, 9]))),
    ]);
    // The count is what the list says, so only the list is compared
    running.modules[0].dtc_count = Err(ReadError::NoReply);
    assert_eq!(diff_scan(&old, &running), []);
}

#[test]
fn the_supported_pids_and_mode_09_pids_and_the_name_are_compared() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    new.ecus[0].pids = Ok(vec![
        (0x0C, Ok(PidValue::Raw(vec![1, 2]))),
        (0x0D, Err(ReadError::NoReply)),
    ]);
    new.ecus[0].supported_info = Ok(vec![0x04, 0x06]);
    new.ecus[0].ecu_name = Ok("ECM-Other".to_owned());
    let changes = diff_scan(&old, &new);
    assert_eq!(
        lines(&changes),
        [
            "7E8 mode 01 PID 05 removed",
            "7E8 mode 01 PID 0D added",
            "7E8 mode 09 PID 02 removed",
            "7E8 mode 09 PID 06 added",
            "7E8 name: \"ECM-EngineControl\" → \"ECM-Other\"",
        ]
    );
    let mut cut = old.clone();
    cut.ecus[0].pids_cut_short = Some((0x20, ReadError::NoReply));
    assert_eq!(
        lines(&diff_scan(&old, &cut)),
        ["7E8 PID list cut short at 20 (was complete)"]
    );
    assert_eq!(
        lines(&diff_scan(&cut, &old)),
        ["7E8 PID list complete (was cut short at 20)"]
    );
    let mut renamed = old.clone();
    renamed.ecus[0].ecu_name = Err(ReadError::NoReply);
    assert_eq!(
        lines(&diff_scan(&old, &renamed)),
        ["7E8 name: \"ECM-EngineControl\" → (no reply)"]
    );
}

#[test]
fn pending_and_permanent_dtcs_are_new_or_cleared_like_stored_ones() {
    let mut old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    old.ecus[0].pending_dtcs = Some(Ok(vec![Dtc::new(0x0401)]));
    old.ecus[0].permanent_dtcs = Some(Ok(vec![Dtc::new(0x0420)]));
    let mut new = old.clone();
    new.ecus[0].pending_dtcs = Some(Ok(vec![Dtc::new(0x0171)]));
    new.ecus[0].permanent_dtcs = Some(Ok(vec![Dtc::new(0x0420), Dtc::new(0x0300)]));
    let changes = diff_scan(&old, &new);
    assert_eq!(
        changes,
        [
            Change::ObdPendingDtcNew {
                source: 0x7E8,
                dtc: Dtc::new(0x0171)
            },
            Change::ObdPendingDtcCleared {
                source: 0x7E8,
                dtc: Dtc::new(0x0401)
            },
            Change::ObdPermanentDtcNew {
                source: 0x7E8,
                dtc: Dtc::new(0x0300)
            },
        ]
    );
    assert_eq!(
        lines(&changes),
        [
            "7E8 pending DTC new: P0171",
            "7E8 pending DTC cleared: P0401",
            "7E8 permanent DTC new: P0300",
        ]
    );
    new.ecus[0].permanent_dtcs = Some(Ok(vec![]));
    assert_eq!(
        lines(&diff_scan(&old, &new))[2],
        "7E8 permanent DTC cleared: P0420"
    );
}

#[test]
fn a_pending_or_permanent_list_that_failed_is_one_change_and_not_supported_is_a_failure() {
    let mut old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    old.ecus[0].permanent_dtcs = Some(Ok(vec![Dtc::new(0x0420)]));
    let mut new = old.clone();
    let not_supported = ReadError::Reply(ReplyError::Negative(NegativeResponse {
        sid: 0x0A,
        nrc: Nrc::ServiceNotSupported,
    }));
    new.ecus[0].permanent_dtcs = Some(Err(not_supported.clone()));
    new.ecus[0].pending_dtcs = Some(Err(ReadError::NoReply));
    assert_eq!(
        diff_scan(&old, &new),
        [
            Change::Unreadable {
                scope: Scope::Ecu { source: 0x7E8 },
                list: List::ObdPendingDtcs,
                old: None,
                new: Some(ReadError::NoReply),
            },
            Change::Unreadable {
                scope: Scope::Ecu { source: 0x7E8 },
                list: List::ObdPermanentDtcs,
                old: None,
                new: Some(not_supported),
            },
        ]
    );
    // Failing the same way twice isn't a change.
    old.ecus[0].pending_dtcs = Some(Err(ReadError::NoReply));
    new.ecus[0].permanent_dtcs = old.ecus[0].permanent_dtcs.clone();
    assert_eq!(diff_scan(&old, &new), []);
}

#[test]
fn a_read_a_side_never_made_is_not_compared() {
    // A document from before the read has none of these.
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut older = old.clone();
    older.ecus[0].monitor_status = None;
    older.ecus[0].pending_dtcs = None;
    older.ecus[0].permanent_dtcs = None;
    let mut new = old.clone();
    new.ecus[0].pending_dtcs = Some(Ok(vec![Dtc::new(0x0171)]));
    new.ecus[0].permanent_dtcs = Some(Err(ReadError::NoReply));
    new.ecus[0].monitor_status = Some(Ok(status(0x81, 0x2F, 0x28, 0x20)));
    assert_eq!(diff_scan(&older, &new), []);
    assert_eq!(diff_scan(&new, &older), []);
}

#[test]
fn the_mil_turning_on_or_off_is_a_change() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    new.ecus[0].monitor_status = Some(Ok(status(0x81, 0x2F, 0x28, 0x20)));
    let changes = diff_scan(&old, &new);
    assert_eq!(
        changes,
        [Change::MilChanged {
            source: 0x7E8,
            old: false,
            new: true
        }]
    );
    assert_eq!(lines(&changes), ["7E8 MIL: off → on"]);
    assert_eq!(lines(&diff_scan(&new, &old)), ["7E8 MIL: on → off"]);
}

#[test]
fn a_monitor_going_complete_or_incomplete_is_a_change_in_bit_order() {
    // The A7 engine's diesel monitors: boost (D3) and exhaust gas sensor (D5) supported, the
    // sensor incomplete.
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    // The sensor completes and the boost monitor, supported and complete, doesn't.
    new.ecus[0].monitor_status = Some(Ok(status(0x00, 0x2F, 0x28, 0x08)));
    let changes = diff_scan(&old, &new);
    assert_eq!(
        lines(&changes),
        [
            "7E8 monitor boost pressure: complete → incomplete",
            "7E8 monitor exhaust gas sensor: incomplete → complete",
        ]
    );
    assert_eq!(
        changes[0],
        Change::MonitorChanged {
            source: 0x7E8,
            monitor: MonitorKind::BoostPressure,
            old: true,
            new: false,
        }
    );
}

#[test]
fn a_monitor_only_counts_where_both_reads_support_it() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    // Nothing supported: the incomplete bits mean nothing then. And a spark engine's monitors
    // aren't the diesel's: only those both have are compared.
    new.ecus[0].monitor_status = Some(Ok(status(0x00, 0x2F, 0x00, 0xFF)));
    assert_eq!(diff_scan(&old, &new), []);
    new.ecus[0].monitor_status = Some(Ok(status(0x00, 0x27, 0xFF, 0xFF)));
    assert_eq!(diff_scan(&old, &new), []);
    // Where the engine type changes, the three common monitors still compare.
    new.ecus[0].monitor_status = Some(Ok(status(0x00, 0x37, 0xFF, 0xFF)));
    assert_eq!(
        lines(&diff_scan(&old, &new)),
        ["7E8 monitor misfire: complete → incomplete"]
    );
}

#[test]
fn a_status_that_failed_is_one_change() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    new.ecus[0].monitor_status = Some(Err(ReadError::NoReply));
    assert_eq!(
        diff_scan(&old, &new),
        [Change::Unreadable {
            scope: Scope::Ecu { source: 0x7E8 },
            list: List::MonitorStatus,
            old: None,
            new: Some(ReadError::NoReply),
        }]
    );
}

#[test]
fn freeze_frames_and_mode_06_ids_are_not_compared() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    new.ecus[0].freeze_frame = Some(Ok(FreezeFrame {
        cause: Some(Dtc::new(0x0299)),
        pids: Ok(vec![(0x04, Ok(PidValue::Raw(vec![1])))]),
        pids_cut_short: Some((0x20, ReadError::NoReply)),
    }));
    new.ecus[0].monitor_ids = Some(Ok(vec![0x01, 0x21]));
    new.ecus[0].monitor_ids_cut_short = Some((0x40, ReadError::NoReply));
    assert_eq!(diff_scan(&old, &new), []);
}

#[test]
fn stored_emissions_dtcs_are_new_or_cleared() {
    let old = scan(vec![obd_ecu(0x7E8)], Vec::new());
    let mut new = old.clone();
    new.ecus[0].stored_dtcs = Ok(vec![Dtc::new(0x0171), Dtc::new(0x0300)]);
    let changes = diff_scan(&old, &new);
    assert_eq!(
        changes,
        [
            Change::ObdDtcNew {
                source: 0x7E8,
                dtc: Dtc::new(0x0171)
            },
            Change::ObdDtcNew {
                source: 0x7E8,
                dtc: Dtc::new(0x0300)
            },
            Change::ObdDtcCleared {
                source: 0x7E8,
                dtc: Dtc::new(0x0401)
            },
        ]
    );
    assert_eq!(
        lines(&changes),
        [
            "7E8 DTC new: P0171",
            "7E8 DTC new: P0300",
            "7E8 DTC cleared: P0401",
        ]
    );
    new.ecus[0].stored_dtcs = Err(ReadError::NoReply);
    assert_eq!(
        diff_scan(&old, &new),
        [Change::Unreadable {
            scope: Scope::Ecu { source: 0x7E8 },
            list: List::ObdDtcs,
            old: None,
            new: Some(ReadError::NoReply),
        }]
    );
}

#[test]
fn a_modules_dtcs_are_new_cleared_or_changed_in_status() {
    let old = scan(Vec::new(), vec![module_scan("engine", 0x7E8)]);
    let mut new = old.clone();
    new.modules[0].dtcs = Ok(vec![
        DtcRecord {
            dtc: UdsDtc::new(0x16A0),
            status: DtcStatus(0x28),
        },
        DtcRecord {
            dtc: UdsDtc::new(0xAA00),
            status: DtcStatus(0x08),
        },
    ]);
    let changes = diff_scan(&old, &new);
    assert_eq!(
        lines(&changes),
        [
            "engine DTC 0016A0 status: confirmed → confirmed, failed since clear",
            "engine DTC new: 00AA00 (confirmed)",
        ]
    );
    new.modules[0].dtcs = Ok(Vec::new());
    assert_eq!(
        lines(&diff_scan(&old, &new)),
        ["engine DTC cleared: 0016A0 (confirmed)"]
    );
    new.modules[0].dtcs = Err(ReadError::StillPending);
    assert_eq!(
        lines(&diff_scan(&old, &new)),
        [
            "engine DTCs can't be compared: old read, new the module said it was busy (response-pending) but didn't answer in time"
        ]
    );
}

#[test]
fn a_module_that_stopped_answering_is_one_change_beside_its_failed_reads() {
    let old = scan(Vec::new(), vec![module_scan("engine", 0x7E8)]);
    let mut silent = old.clone();
    silent.modules[0].answered = false;
    silent.modules[0].dids = vec![(0xF187, Err(ReadError::NoReply))];
    silent.modules[0].dtcs = Err(ReadError::NoReply);
    let changes = diff_scan(&old, &silent);
    assert_eq!(
        lines(&changes),
        [
            "engine answered → didn't answer",
            "engine F187 \"part\" → (no reply)",
            "engine DTCs can't be compared: old read, new no reply",
        ]
    );
    assert_eq!(
        changes[0],
        Change::AnsweredChanged {
            module: module_id("engine", 0x7E8),
            old: true,
            new: false
        }
    );
    assert_eq!(
        lines(&diff_scan(&silent, &old))[0],
        "engine didn't answer → answered"
    );
}

#[test]
fn a_scan_with_a_new_module_or_ecu_reports_only_that() {
    let none = scan(Vec::new(), Vec::new());
    let full = scan(vec![obd_ecu(0x7E8)], vec![module_scan("engine", 0x7E8)]);
    assert_eq!(
        lines(&diff_scan(&none, &full)),
        ["7E8 ECU added", "module added: engine (0x7E8)"]
    );
    assert_eq!(
        lines(&diff_scan(&full, &none)),
        ["7E8 ECU removed", "module removed: engine (0x7E8)"]
    );
}

// ---- sweeps, read-dids and VINs ---------------------------------------------------------------

fn sweep(found: Vec<(u16, Result<Vec<u8>, ReadError>)>) -> Sweep {
    Sweep {
        found,
        stop: None,
        still_extended: None,
        out_of_step: false,
    }
}

#[test]
fn a_sweep_compares_the_dids_found_inside_the_range_given() {
    let module = UdsModule {
        name: "head-up display".to_owned(),
        request_id: 0x7A0,
        response_id: 0x7A8,
    };
    let old = sweep(vec![
        (0x0600, Ok(vec![1])),
        (0x0601, Ok(vec![2])),
        (0x0602, Err(ReadError::NoReply)),
        (0x0700, Ok(vec![9])),
    ]);
    let new = sweep(vec![
        (0x0600, Ok(vec![1])),
        (0x0601, Ok(vec![3])),
        (0x0603, Ok(vec![4])),
        (0x0700, Ok(vec![8])),
    ]);
    let changes = diff_sweep(&module, &old, &new, 0x0600..=0x06FF);
    assert_eq!(
        lines(&changes),
        [
            "head-up display 0601 [02] → [03]",
            "head-up display 0602 (no reply) → (absent)",
            "head-up display 0603 (absent) → [04]",
        ]
    );
    assert_eq!(
        changes[0],
        Change::DidChanged {
            module: module_id("head-up display", 0x7A8),
            did: 0x0601,
            old: Some(Ok(DidValue::Bytes(vec![2]))),
            new: Some(Ok(DidValue::Bytes(vec![3]))),
        }
    );
    // An empty range compares nothing
    let (high, low) = (0x0800, 0x0700);
    let empty = high..=low;
    assert_eq!(diff_sweep(&module, &old, &new, empty), []);
}

#[test]
fn a_multi_did_read_compares_each_split_did_and_the_unsplit_bytes() {
    let module = UdsModule::obd_transmission();
    let read = |split: Vec<(u16, Vec<u8>)>, unsplit: Vec<u8>| {
        Ok(DidsData {
            split,
            left_out: vec![],
            unsplit,
        })
    };
    let old = read(
        vec![(0xF189, vec![1]), (0xF191, vec![2])],
        vec![0xF1, 0x90, 7],
    );
    let new = read(
        vec![(0xF189, vec![1]), (0xF191, vec![3])],
        vec![0xF1, 0x90, 8],
    );
    assert_eq!(
        lines(&diff_dids_data(&module, &old, &new)),
        [
            "transmission F191 [02] → [03]",
            "transmission unsplit data [F1 90 07] → [F1 90 08]",
        ]
    );
    assert_eq!(diff_dids_data(&module, &old, &old.clone()), []);
    let failed: Result<DidsData, ReadError> = Err(ReadError::NoReply);
    assert_eq!(
        diff_dids_data(&module, &old, &failed),
        [Change::Unreadable {
            scope: Scope::Module(module_id("transmission", 0x7E9)),
            list: List::Dids,
            old: None,
            new: Some(ReadError::NoReply),
        }]
    );
    assert_eq!(diff_dids_data(&module, &failed, &failed.clone()), []);
}

#[test]
fn a_did_split_in_one_multi_did_read_and_left_out_of_the_other_is_a_change() {
    let module = UdsModule::obd_transmission();
    let read = |split: Vec<(u16, Vec<u8>)>, left_out: Vec<u16>| {
        Ok(DidsData {
            split,
            left_out,
            unsplit: vec![],
        })
    };
    let both = read(vec![(0xF188, vec![1]), (0xF189, vec![2])], vec![]);
    let left_out = read(vec![(0xF189, vec![2])], vec![0xF188]);
    assert_eq!(
        lines(&diff_dids_data(&module, &both, &left_out)),
        ["transmission F188 [01] → (absent)"]
    );
    assert_eq!(
        lines(&diff_dids_data(&module, &left_out, &both)),
        ["transmission F188 (absent) → [01]"]
    );
    assert_eq!(diff_dids_data(&module, &left_out, &left_out.clone()), []);
}

#[test]
fn vins_are_compared_by_source_and_only_a_changed_one_is_shown() {
    let vin = |id: u32, vin: &str| (id, vin.to_owned());
    let old = [
        vin(0x7E8, "WAU2MBFC6EN093415"),
        vin(0x7E9, "WAU2MBFC6EN093415"),
    ];
    assert_eq!(diff_vins(&old, &old), []);
    let new = [
        vin(0x7E9, "WAU2MBFC6EN093415"),
        vin(0x7E8, "WBAXXXXXXXXXXXXXX"),
    ];
    let changes = diff_vins(&old, &new);
    assert_eq!(
        lines(&changes),
        ["7E8 VIN WAU2MBFC6EN093415 → WBAXXXXXXXXXXXXXX"]
    );
    assert_eq!(
        lines(&diff_vins(&old, &[vin(0x7E8, "WAU2MBFC6EN093415")])),
        ["7E9 ECU removed"]
    );
    assert_eq!(
        lines(&diff_vins(&[], &old)),
        ["7E8 ECU added", "7E9 ECU added"]
    );
    // No VIN text for an ECU that only came or went
    assert!(!lines(&diff_vins(&[], &old)).concat().contains("WAU"));
}

// ---- the JSON form ----------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod json {
    use serde_json::{Value, json};

    use super::*;

    fn written(changes: &[Change]) -> Value {
        serde_json::to_value(changes).unwrap()
    }

    #[test]
    fn each_change_is_an_object_tagged_with_its_name_and_in_the_documents_forms() {
        let old = engine_calibrations("A", [0x9B, 0xF7, 0x47, 0x0D]);
        let new = fingerprint(
            vec![calibration(0x7E8, &[Some("B")], &[[0; 4]])],
            vec![identification(
                "engine",
                0x7E8,
                vec![(0xF187, Err(ReadError::NoReply))],
            )],
        );
        let mut changes = diff_fingerprint(&old, &new);
        changes.push(Change::EcuNameChanged {
            source: 0x17FE_0010,
            old: Ok("x".to_owned()),
            new: Err(ReadError::NoReply),
        });
        assert_eq!(
            written(&changes),
            json!([
                {"change": "CalidChanged", "source": "7E8", "slot": 1, "old": "A", "new": "B"},
                {"change": "CvnChanged", "source": "7E8", "slot": 1, "old": "9BF7470D", "new": "00000000"},
                {"change": "ModuleAdded", "module": {"name": "engine", "response_id": "7E8"}},
                {"change": "EcuNameChanged", "source": "17FE0010", "old": {"value": "x"}, "new": {"error": "NoReply"}},
            ])
        );
    }

    #[test]
    fn the_readiness_and_dtc_list_changes_are_written_as_documented() {
        let source = 0x7E8;
        let dtc = Dtc::new(0x0299);
        let changes = [
            Change::ObdPendingDtcNew { source, dtc },
            Change::ObdPendingDtcCleared { source, dtc },
            Change::ObdPermanentDtcNew { source, dtc },
            Change::ObdPermanentDtcCleared { source, dtc },
            Change::MilChanged {
                source,
                old: false,
                new: true,
            },
            Change::MonitorChanged {
                source,
                monitor: MonitorKind::ExhaustGasSensor,
                old: false,
                new: true,
            },
            Change::Unreadable {
                scope: Scope::Ecu { source },
                list: List::MonitorStatus,
                old: None,
                new: Some(ReadError::NoReply),
            },
            Change::Unreadable {
                scope: Scope::Ecu { source },
                list: List::ObdPermanentDtcs,
                old: None,
                new: Some(ReadError::NoReply),
            },
        ];
        assert_eq!(
            written(&changes),
            json!([
                {"change": "ObdPendingDtcNew", "source": "7E8", "dtc": "P0299"},
                {"change": "ObdPendingDtcCleared", "source": "7E8", "dtc": "P0299"},
                {"change": "ObdPermanentDtcNew", "source": "7E8", "dtc": "P0299"},
                {"change": "ObdPermanentDtcCleared", "source": "7E8", "dtc": "P0299"},
                {"change": "MilChanged", "source": "7E8", "old": false, "new": true},
                {"change": "MonitorChanged", "source": "7E8", "monitor": "exhaust_gas_sensor",
                 "old": false, "new": true},
                {"change": "Unreadable", "scope": {"kind": "Ecu", "source": "7E8"},
                 "list": "MonitorStatus", "old": null, "new": "NoReply"},
                {"change": "Unreadable", "scope": {"kind": "Ecu", "source": "7E8"},
                 "list": "ObdPermanentDtcs", "old": null, "new": "NoReply"},
            ])
        );
    }

    #[test]
    fn a_did_on_one_side_only_is_null_and_a_failed_list_names_its_scope() {
        let changes = [
            Change::DidChanged {
                module: module_id("engine", 0x7E8),
                did: 0xF187,
                old: None,
                new: Some(Ok(DidValue::Bytes(vec![0x1A, 0x2A]))),
            },
            Change::Unreadable {
                scope: Scope::Module(module_id("engine", 0x7E8)),
                list: List::UdsDtcs,
                old: None,
                new: Some(ReadError::NoReply),
            },
            Change::Unreadable {
                scope: Scope::Ecu { source: 0x7E8 },
                list: List::Calids,
                old: Some(ReadError::StillPending),
                new: None,
            },
            Change::UdsDtcNew {
                module: module_id("engine", 0x7E8),
                dtc: UdsDtc::new(0x16A0),
                status: DtcStatus(0x2F),
            },
            Change::ObdPidAdded {
                source: 0x7E8,
                pid: 0x0C,
            },
        ];
        assert_eq!(
            written(&changes),
            json!([
                {"change": "DidChanged", "module": {"name": "engine", "response_id": "7E8"},
                 "did": "F187", "old": null, "new": {"value": {"Bytes": "1A 2A"}}},
                {"change": "Unreadable", "scope": {"kind": "Module", "name": "engine", "response_id": "7E8"},
                 "list": "UdsDtcs", "old": null, "new": "NoReply"},
                {"change": "Unreadable", "scope": {"kind": "Ecu", "source": "7E8"},
                 "list": "Calids", "old": "StillPending", "new": null},
                {"change": "UdsDtcNew", "module": {"name": "engine", "response_id": "7E8"},
                 "dtc": "0016A0", "status": "2F"},
                {"change": "ObdPidAdded", "source": "7E8", "pid": "0C"},
            ])
        );
    }
}

// ---- properties -------------------------------------------------------------------------------

fn read_error() -> impl Strategy<Value = ReadError> {
    prop_oneof![
        Just(ReadError::NoReply),
        Just(ReadError::StillPending),
        Just(ReadError::NeedsExtendedSession),
        (0usize..4, 0usize..4).prop_map(|(calids, cvns)| ReadError::CountMismatch { calids, cvns }),
    ]
}

fn did_value() -> impl Strategy<Value = Result<DidValue, ReadError>> {
    prop_oneof![
        "[A-Z0-9]{0,6}".prop_map(|t| Ok(DidValue::Text(t))),
        prop::collection::vec(any::<u8>(), 0..4).prop_map(|b| Ok(DidValue::Bytes(b))),
        Just(Ok(DidValue::NotSet)),
        read_error().prop_map(Err),
    ]
}

fn outcome<T: std::fmt::Debug>(
    value: impl Strategy<Value = T>,
) -> impl Strategy<Value = Result<T, ReadError>> {
    prop_oneof![value.prop_map(Ok), read_error().prop_map(Err)]
}

fn can_id() -> impl Strategy<Value = u32> {
    prop_oneof![0x7E0u32..0x7F0, 0x17FE_0000u32..0x17FE_0010]
}

// Sources and names that don't repeat, so a list's order is the only thing the property shuffles.
fn unique_by<T: std::fmt::Debug>(
    items: impl Strategy<Value = Vec<T>>,
    key: fn(&T) -> String,
) -> impl Strategy<Value = Vec<T>> {
    items.prop_map(move |items| {
        let mut seen = std::collections::HashSet::new();
        items
            .into_iter()
            .filter(|item| seen.insert(key(item)))
            .collect()
    })
}

fn arbitrary_fingerprint() -> impl Strategy<Value = Fingerprint> {
    let calibration = (
        can_id(),
        outcome(prop::collection::vec(
            prop::option::of("[A-Z0-9]{1,6}"),
            0..3,
        )),
        outcome(prop::collection::vec(any::<[u8; 4]>().prop_map(Cvn), 0..3)),
    )
        .prop_map(|(source, calids, cvns)| Calibration {
            source,
            calids,
            cvns,
        });
    let module = (
        "[a-z]{1,4}",
        can_id(),
        prop::collection::vec((any::<u16>(), did_value()), 0..4),
    )
        .prop_map(|(name, response_id, dids)| {
            identification(&name, response_id, unique_dids(dids))
        });
    (
        unique_by(prop::collection::vec(calibration, 0..3), |c| {
            c.source.to_string()
        }),
        unique_by(prop::collection::vec(module, 0..3), |m| {
            format!("{}/{}", m.name, m.response_id)
        }),
    )
        .prop_map(|(ecus, modules)| Fingerprint { ecus, modules })
}

fn unique_dids(dids: Vec<Did>) -> Vec<Did> {
    let mut seen = std::collections::HashSet::new();
    dids.into_iter()
        .filter(|(did, _)| seen.insert(*did))
        .collect()
}

proptest! {
    #[test]
    fn a_fingerprint_has_no_changes_from_itself(one in arbitrary_fingerprint()) {
        prop_assert_eq!(diff_fingerprint(&one, &one.clone()), Vec::new());
    }

    #[test]
    fn the_order_of_the_lists_never_changes_the_changes(
        old in arbitrary_fingerprint(),
        new in arbitrary_fingerprint(),
    ) {
        let expected = diff_fingerprint(&old, &new);
        let mut flipped = new.clone();
        flipped.ecus.reverse();
        flipped.modules.reverse();
        flipped.modules.iter_mut().for_each(|m| m.dids.reverse());
        prop_assert_eq!(diff_fingerprint(&old, &flipped), expected);
    }

    #[test]
    fn what_was_added_going_one_way_is_removed_going_the_other(
        old in arbitrary_fingerprint(),
        new in arbitrary_fingerprint(),
    ) {
        let count = |changes: &[Change], wanted: fn(&Change) -> bool| changes.iter().filter(|c| wanted(c)).count();
        let forward = diff_fingerprint(&old, &new);
        let back = diff_fingerprint(&new, &old);
        prop_assert_eq!(forward.len(), back.len());
        prop_assert_eq!(
            count(&forward, |c| matches!(c, Change::EcuAdded { .. })),
            count(&back, |c| matches!(c, Change::EcuRemoved { .. }))
        );
        prop_assert_eq!(
            count(&forward, |c| matches!(c, Change::ModuleRemoved { .. })),
            count(&back, |c| matches!(c, Change::ModuleAdded { .. }))
        );
    }
}

#[test]
fn text_from_a_document_reaches_the_terminal_as_printable_ascii() {
    let evil = "ok\u{1b}[31m\u{202E}é\\";
    let old = engine_calibrations("A", [1; 4]);
    let new = engine_calibrations(evil, [1; 4]);
    let line = diff_fingerprint(&old, &new)[0].to_string();
    assert_eq!(
        line,
        "7E8 CALID 1: \"A\" → \"ok\\u{1b}[31m\\u{202e}\\u{e9}\\\\\""
    );
    assert!(line.chars().all(|c| (' '..='~').contains(&c) || c == '→'));
    let module =
        |name: &str| fingerprint(Vec::new(), vec![identification(name, 0x7E8, Vec::new())]);
    let line = diff_fingerprint(&module("a"), &module("\u{1b}]0;x\u{7}"))[0].to_string();
    assert!(line.starts_with("module added: "));
    assert!(
        !line.contains('\u{1b}') && !line.contains('\u{7}'),
        "{line:?}"
    );
}

#[test]
fn every_ecu_change_has_a_line() {
    let source = 0x7E8;
    let ecu = [
        Change::EcuAdded { source },
        Change::EcuRemoved { source },
        Change::CalidChanged {
            source,
            slot: 1,
            old: None,
            new: None,
        },
        Change::CalidAdded {
            source,
            slot: 1,
            calid: None,
        },
        Change::CalidRemoved {
            source,
            slot: 1,
            calid: None,
        },
        Change::CvnChanged {
            source,
            slot: 1,
            old: Cvn([0; 4]),
            new: Cvn([1; 4]),
        },
        Change::CvnAdded {
            source,
            slot: 1,
            cvn: Cvn([0; 4]),
        },
        Change::CvnRemoved {
            source,
            slot: 1,
            cvn: Cvn([0; 4]),
        },
        Change::ObdPidAdded { source, pid: 5 },
        Change::ObdPidRemoved { source, pid: 5 },
        Change::PidsCutShortChanged {
            source,
            old: None,
            new: Some(0x40),
        },
        Change::ObdInfoAdded { source, pid: 4 },
        Change::ObdInfoRemoved { source, pid: 4 },
        Change::EcuNameChanged {
            source,
            old: Ok("a".to_owned()),
            new: Ok("b".to_owned()),
        },
        Change::ObdDtcNew {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::ObdDtcCleared {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::ObdPendingDtcNew {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::ObdPendingDtcCleared {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::ObdPermanentDtcNew {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::ObdPermanentDtcCleared {
            source,
            dtc: Dtc::new(0x0401),
        },
        Change::MilChanged {
            source,
            old: false,
            new: true,
        },
        Change::MonitorChanged {
            source,
            monitor: MonitorKind::Catalyst,
            old: false,
            new: true,
        },
        Change::VinChanged {
            source,
            old: "a".to_owned(),
            new: "b".to_owned(),
        },
    ];
    assert!(ecu.iter().all(|change| !change.to_string().is_empty()));
}

#[test]
fn every_module_change_has_a_line() {
    let module = module_id("engine", 0x7E8);
    let rest = [
        Change::ModuleAdded {
            module: module.clone(),
        },
        Change::ModuleRemoved {
            module: module.clone(),
        },
        Change::AnsweredChanged {
            module: module.clone(),
            old: true,
            new: false,
        },
        Change::DidChanged {
            module: module.clone(),
            did: 0xF187,
            old: None,
            new: None,
        },
        Change::UnsplitChanged {
            module: module.clone(),
            old: vec![1],
            new: vec![2],
        },
        Change::UdsDtcNew {
            module: module.clone(),
            dtc: UdsDtc::new(1),
            status: DtcStatus(8),
        },
        Change::UdsDtcCleared {
            module: module.clone(),
            dtc: UdsDtc::new(1),
            status: DtcStatus(8),
        },
        Change::UdsDtcStatusChanged {
            module: module.clone(),
            dtc: UdsDtc::new(1),
            old: DtcStatus(8),
            new: DtcStatus(0),
        },
        Change::Unreadable {
            scope: Scope::Module(module),
            list: List::Dids,
            old: None,
            new: None,
        },
    ];
    assert!(rest.iter().all(|change| !change.to_string().is_empty()));
}

// ---- text, bytes and the markers between them ----------------------------------------------

fn did_line(
    old: Option<Result<DidValue, ReadError>>,
    new: Option<Result<DidValue, ReadError>>,
) -> String {
    Change::DidChanged {
        module: module_id("engine", 0x7E8),
        did: 0xF187,
        old,
        new,
    }
    .to_string()
}

#[test]
fn a_dids_text_bytes_and_markers_each_read_differently() {
    let text = |value: &str| Some(Ok(DidValue::Text(value.to_owned())));
    let bytes = |value: &[u8]| Some(Ok(DidValue::Bytes(value.to_vec())));
    // Text that looks like the bytes it isn't
    assert_eq!(
        did_line(text("[01]"), bytes(&[1])),
        "engine F187 \"[01]\" → [01]"
    );
    // Text that is a marker
    assert_eq!(
        did_line(text("(absent)"), None),
        "engine F187 \"(absent)\" → (absent)"
    );
    assert_eq!(
        did_line(text("(not set)"), Some(Ok(DidValue::NotSet))),
        "engine F187 \"(not set)\" → (not set)"
    );
    assert_eq!(
        did_line(text("(no reply)"), Some(Err(ReadError::NoReply))),
        "engine F187 \"(no reply)\" → (no reply)"
    );
    // Quotes and backslashes in the text stay readable back
    assert_eq!(
        did_line(text("a\"b\\c"), text("")),
        "engine F187 \"a\\\"b\\\\c\" → \"\""
    );
    assert_eq!(
        did_line(text("0005"), text("0006")),
        "engine F187 \"0005\" → \"0006\""
    );
}

#[test]
fn a_calibration_id_and_an_ecu_name_that_spell_a_marker_are_quoted() {
    let old = engine_calibrations("4G0907589F", [1; 4]);
    let marker = fingerprint(
        vec![Calibration {
            source: 0x7E8,
            calids: Ok(vec![None]),
            cvns: Ok(vec![Cvn([1; 4])]),
        }],
        Vec::new(),
    );
    assert_eq!(
        lines(&diff_fingerprint(&old, &marker)),
        ["7E8 CALID 1: \"4G0907589F\" → (empty)"]
    );
    let literal = engine_calibrations("(empty)", [1; 4]);
    assert_eq!(
        lines(&diff_fingerprint(&marker, &literal)),
        ["7E8 CALID 1: (empty) → \"(empty)\""]
    );
    let name = Change::EcuNameChanged {
        source: 0x7E8,
        old: Err(ReadError::NoReply),
        new: Ok("(no reply)".to_owned()),
    };
    assert_eq!(name.to_string(), "7E8 name: (no reply) → \"(no reply)\"");
}

// ---- repeats in the other kinds of result ---------------------------------------------------

#[test]
fn a_scan_that_repeats_an_ecu_module_did_or_dtc_is_refused() {
    let clean = scan(vec![obd_ecu(0x7E8)], vec![module_scan("engine", 0x7E8)]);
    let record = |dtc: u32, status: u8| DtcRecord {
        dtc: UdsDtc::new(dtc),
        status: DtcStatus(status),
    };
    let mut ecu = clean.clone();
    ecu.ecus.push(obd_ecu(0x7E8));
    let mut module = clean.clone();
    module.modules.push(module_scan("engine", 0x7E8));
    let mut did = clean.clone();
    did.modules[0].dids.push(text(0xF187, "other"));
    let mut dtc = clean.clone();
    dtc.modules[0].dtcs = Ok(vec![record(0x16A0, 8), record(0x16A0, 0)]);
    let dtc_twice = || Ok(vec![Dtc::new(0x0171), Dtc::new(0x0171)]);
    let mut stored = clean.clone();
    stored.ecus[0].stored_dtcs = dtc_twice();
    let mut pid = clean.clone();
    pid.ecus[0].pids = Ok(vec![(0x05, Ok(PidValue::Raw(vec![1]))); 2]);
    let mut info = clean.clone();
    info.ecus[0].supported_info = Ok(vec![0x02, 0x02]);
    let mut pending = clean.clone();
    pending.ecus[0].pending_dtcs = Some(dtc_twice());
    let mut permanent = clean.clone();
    permanent.ecus[0].permanent_dtcs = Some(dtc_twice());
    for (bad, entry) in [
        (&ecu, "ECU 7E8"),
        (&module, "module engine (0x7E8)"),
        (&did, "DID F187 of engine (0x7E8)"),
        (&dtc, "DTC 0016A0 of engine (0x7E8)"),
        (&stored, "stored DTC P0171 of ECU 7E8"),
        (&pid, "PID 05 of ECU 7E8"),
        (&info, "mode 09 PID 02 of ECU 7E8"),
        (&pending, "pending DTC P0171 of ECU 7E8"),
        (&permanent, "permanent DTC P0171 of ECU 7E8"),
    ] {
        let expected = |input| DuplicateError {
            input,
            entry: entry.to_owned(),
        };
        assert_eq!(
            diff::diff_scan(bad, &clean).unwrap_err(),
            expected(Input::Old)
        );
        assert_eq!(
            diff::diff_scan(&clean, bad).unwrap_err(),
            expected(Input::New)
        );
    }
    // A DTC list that failed has nothing to repeat
    let mut failed = clean.clone();
    failed.modules[0].dtcs = Err(ReadError::NoReply);
    failed.ecus[0].stored_dtcs = Err(ReadError::NoReply);
    failed.ecus[0].pids = Err(ReadError::NoReply);
    failed.ecus[0].pending_dtcs = Some(Err(ReadError::NoReply));
    assert_eq!(diff_scan(&failed, &failed), []);
    // A repeat is refused even when the other document never made the read
    let mut unread = clean.clone();
    unread.ecus[0].pending_dtcs = None;
    unread.ecus[0].permanent_dtcs = None;
    assert!(diff::diff_scan(&pending, &unread).is_err());
    assert!(diff::diff_scan(&unread, &permanent).is_err());
}

#[test]
fn a_sweep_or_read_that_repeats_a_did_is_refused_but_only_inside_the_range() {
    let module = UdsModule::obd_engine();
    let clean = sweep(vec![(0x0600, Ok(vec![1]))]);
    let twice = sweep(vec![(0x0600, Ok(vec![1])), (0x0600, Ok(vec![2]))]);
    let error = diff::diff_sweep(&module, &clean, &twice, 0x0600..=0x06FF).unwrap_err();
    assert_eq!(error.input, Input::New);
    assert!(error.entry.starts_with("DID 0600 of "), "{error}");
    assert!(diff::diff_sweep(&module, &twice, &clean, 0x0600..=0x06FF).is_err());
    // Outside the range compared, a repeat says nothing
    assert!(diff::diff_sweep(&module, &twice, &clean, 0x0700..=0x07FF).is_ok());

    let read = |split: Vec<(u16, Vec<u8>)>| -> Result<DidsData, ReadError> {
        Ok(DidsData {
            split,
            left_out: Vec::new(),
            unsplit: Vec::new(),
        })
    };
    let one = read(vec![(0xF189, vec![1])]);
    let two = read(vec![(0xF189, vec![1]), (0xF189, vec![1])]);
    let error = diff::diff_dids_data(&module, &two, &one).unwrap_err();
    assert_eq!(error.input, Input::Old);
    assert!(diff::diff_dids_data(&module, &one, &two).is_err());
    let failed: Result<DidsData, ReadError> = Err(ReadError::NoReply);
    assert!(diff::diff_dids_data(&module, &failed, &failed).is_ok());
}

#[test]
fn vins_that_repeat_an_ecu_are_refused() {
    let vin = |id: u32, vin: &str| (id, vin.to_owned());
    let clean = [vin(0x7E8, "A")];
    let twice = [vin(0x7E8, "B"), vin(0x7E8, "A")];
    let error = diff::diff_vins(&clean, &twice).unwrap_err();
    assert_eq!((error.input, error.entry.as_str()), (Input::New, "ECU 7E8"));
    assert!(diff::diff_vins(&twice, &clean).is_err());
}
