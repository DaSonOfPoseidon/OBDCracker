//! Flow control frames exist only as the answer to an approved request.

use obdcracker_core::isotp::Error;
use obdcracker_safety::{
    ApprovedFlowControl, FeedOutcome, ModuleIds, Policy, Protocol, Rejection, ReplyWindow, Target,
};
use proptest::prelude::*;

const FIRST: [u8; 8] = [0x10, 0x14, 0x62, 0xF1, 0x87, 1, 2, 3];
const CONSECUTIVE_1: [u8; 8] = [0x21, 4, 5, 6, 7, 8, 9, 10];
const CONSECUTIVE_2: [u8; 8] = [0x22, 11, 12, 13, 14, 15, 16, 17];
const SINGLE: [u8; 8] = [0x03, 0x62, 0xF1, 0x87, 0, 0, 0, 0];
const OBD_REQUEST: [u8; 2] = [0x09, 0x02];
const UDS_REQUEST: [u8; 3] = [0x22, 0xF1, 0x87];

fn window(target: Target, payload: &[u8]) -> ReplyWindow {
    let approved = Policy::read_only()
        .approve(Protocol::Uds, target, payload)
        .unwrap();
    ReplyWindow::open(&approved).unwrap()
}

fn broadcast() -> ReplyWindow {
    window(Target::ObdFunctional, &OBD_REQUEST)
}

// The engine at 0x7E0, whose reply ID is 0x7E8.
fn engine() -> ReplyWindow {
    window(Target::Physical(0x7E0), &UDS_REQUEST)
}

// A gateway the policy was narrowed to, so its reply ID is known.
fn gateway() -> ReplyWindow {
    let policy = Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x710,
            reply: 0x77A,
        }])
        .unwrap();
    let approved = policy
        .approve(Protocol::Uds, Target::Physical(0x710), &UDS_REQUEST)
        .unwrap();
    ReplyWindow::open(&approved).unwrap()
}

// A physical ID outside the OBD-II range with no profile, so the reply ID isn't known.
fn unknown_reply() -> ReplyWindow {
    window(Target::Physical(0x710), &UDS_REQUEST)
}

fn token(outcome: FeedOutcome) -> ApprovedFlowControl {
    match outcome {
        FeedOutcome::SendFlowControl(token) => token,
        other => panic!("expected a flow control token, got {other:?}"),
    }
}

#[test]
fn a_broadcast_first_frame_gets_a_token_to_the_ecu_that_sent_it() {
    let mut window = broadcast();
    let token = token(window.feed(0x7E8, &FIRST).unwrap());
    assert_eq!(token.destination_id(), 0x7E0);
    assert!(!token.is_29_bit());
    assert_eq!(token.data(), [0x30, 0x00, 0x00]);
}

#[test]
fn every_broadcast_source_gets_a_token_to_its_own_request_id() {
    for source in 0x7E8..=0x7EF {
        let token = token(broadcast().feed(source, &FIRST).unwrap());
        assert_eq!(token.destination_id(), source - 8, "{source:#X}");
    }
}

#[test]
fn broadcast_sources_outside_the_response_range_are_ignored() {
    // One below and one above 0x7E8..=0x7EF, and the broadcast request ID itself.
    for source in [0x7E7, 0x7F0, 0x7DF, 0x7E0, 0x000, 0x7FF] {
        let mut window = broadcast();
        assert_eq!(
            window.feed(source, &FIRST).unwrap(),
            FeedOutcome::Ignored,
            "{source:#X}"
        );
        // Not even a single frame from there completes.
        assert_eq!(
            window.feed(source, &SINGLE).unwrap(),
            FeedOutcome::Ignored,
            "{source:#X}"
        );
    }
}

#[test]
fn a_physical_window_answers_only_the_modules_reply_id() {
    let token = token(engine().feed(0x7E8, &FIRST).unwrap());
    assert_eq!(token.destination_id(), 0x7E0);
    for source in [0x7E7, 0x7E9, 0x7E0, 0x7DF, 0x7EF] {
        let mut window = engine();
        assert_eq!(window.feed(source, &FIRST).unwrap(), FeedOutcome::Ignored);
        assert_eq!(window.feed(source, &SINGLE).unwrap(), FeedOutcome::Ignored);
    }
}

#[test]
fn a_narrowed_module_is_answered_on_its_profile_ids() {
    let token = token(gateway().feed(0x77A, &FIRST).unwrap());
    assert_eq!(token.destination_id(), 0x710);
    assert!(!token.is_29_bit());
    let mut window = gateway();
    assert_eq!(window.feed(0x77B, &FIRST).unwrap(), FeedOutcome::Ignored);
    // The request ID is not a source.
    assert_eq!(window.feed(0x710, &FIRST).unwrap(), FeedOutcome::Ignored);
}

#[test]
fn a_29_bit_module_gets_a_29_bit_token() {
    let approved = Policy::read_only()
        .approve(Protocol::Uds, Target::Physical29(0x18DA_10F1), &UDS_REQUEST)
        .unwrap();
    assert_eq!(approved.reply_id(), Some(0x18DA_F110));
    let mut window = ReplyWindow::open(&approved).unwrap();
    assert_eq!(
        window.feed(0x18DA_F111, &FIRST).unwrap(),
        FeedOutcome::Ignored
    );
    let token = token(window.feed(0x18DA_F110, &FIRST).unwrap());
    assert_eq!(token.destination_id(), 0x18DA_10F1);
    assert!(token.is_29_bit());
    assert_eq!(token.data(), [0x30, 0x00, 0x00]);
}

#[test]
fn tp20_requests_open_no_window() {
    let policy = Policy::read_only();
    let setup = policy.approve_tp20_setup(0x01).unwrap();
    assert_eq!(
        ReplyWindow::open(&setup).unwrap_err(),
        Rejection::WrongTarget
    );
    let channel = policy
        .tp20_channel(&setup, 0x201, &[0x00, 0xD0, 0x00, 0x03, 0x40, 0x07, 0x01])
        .unwrap();
    let keep_alive = policy.approve_tp20_keep_alive(&channel).unwrap();
    assert_eq!(
        ReplyWindow::open(&keep_alive).unwrap_err(),
        Rejection::WrongTarget
    );
}

#[test]
fn an_unknown_reply_id_gets_single_frames_but_never_a_token() {
    let mut window = unknown_reply();
    assert_eq!(
        window.feed(0x77A, &SINGLE).unwrap(),
        FeedOutcome::Complete {
            source: 0x77A,
            payload: vec![0x62, 0xF1, 0x87]
        }
    );
    // Whoever sends a first frame, nothing is minted and nothing errors.
    for source in [0x77A, 0x7E8, 0x000, 0x7DF, u32::MAX] {
        assert_eq!(
            window.feed(source, &FIRST).unwrap(),
            FeedOutcome::NoFlowControl { source }
        );
    }
    // The first frame started no transfer: its consecutive frames are foreign traffic.
    assert_eq!(
        window.feed(0x77A, &CONSECUTIVE_1).unwrap(),
        FeedOutcome::Ignored
    );
    assert_eq!(
        window.feed(0x77A, &CONSECUTIVE_2).unwrap(),
        FeedOutcome::Ignored
    );
}

#[test]
fn an_unknown_reply_id_ignores_everything_else() {
    let mut window = unknown_reply();
    for bytes in [
        &[][..],
        &[0x00, 0x00][..],
        &[0x05, 1][..],
        &[0x30, 0x00, 0x00, 0, 0, 0, 0, 0][..],
        &[0xF0; 8][..],
        &[0x01; 9][..],
        &[0x10, 0x07, 1, 2, 3, 4, 5, 6][..],
    ] {
        assert_eq!(
            window.feed(0x77A, bytes).unwrap(),
            FeedOutcome::Ignored,
            "{bytes:02X?}"
        );
    }
}

#[test]
fn a_whole_multi_frame_reply_completes_after_one_token() {
    let mut window = broadcast();
    token(window.feed(0x7E8, &FIRST).unwrap());
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_1).unwrap(),
        FeedOutcome::Pending
    );
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap(),
        FeedOutcome::Complete {
            source: 0x7E8,
            payload: vec![
                0x62, 0xF1, 0x87, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
            ]
        }
    );
}

#[test]
fn single_frames_and_loose_frames_mint_nothing() {
    let mut window = broadcast();
    assert_eq!(
        window.feed(0x7E8, &SINGLE).unwrap(),
        FeedOutcome::Complete {
            source: 0x7E8,
            payload: vec![0x62, 0xF1, 0x87]
        }
    );
    // A consecutive frame with no first frame.
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_1).unwrap_err(),
        Error::UnexpectedFrame
    );
    // An ECU's own flow control frame.
    assert_eq!(
        window.feed(0x7E8, &[0x30, 0, 0]).unwrap_err(),
        Error::UnexpectedFrame
    );
    // A consecutive frame out of order drops the transfer.
    token(window.feed(0x7E8, &FIRST).unwrap());
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap_err(),
        Error::WrongSequence
    );
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_1).unwrap_err(),
        Error::UnexpectedFrame
    );
}

#[test]
fn bad_first_frames_mint_nothing() {
    for first in [
        // Length 0 is the 32-bit escape, which needs its own bytes.
        &[0x10, 0x00, 1, 2, 3, 4, 5, 6][..],
        // Length 7 fits a single frame.
        &[0x10, 0x07, 1, 2, 3, 4, 5, 6][..],
        // Short data.
        &[0x10, 0x14, 1, 2][..],
        &[][..],
        &[0x10; 9][..],
        // 32-bit length: 5000 bytes, more than the window's buffer.
        &[0x10, 0x00, 0x00, 0x00, 0x13, 0x88, 1, 2][..],
        // 32-bit length: u32::MAX.
        &[0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2][..],
    ] {
        assert!(broadcast().feed(0x7E8, first).is_err(), "{first:02X?}");
    }
    // The longest 12-bit length fits the buffer, so it is a real transfer.
    token(
        broadcast()
            .feed(0x7E8, &[0x1F, 0xFF, 1, 2, 3, 4, 5, 6])
            .unwrap(),
    );
}

#[test]
fn each_first_frame_is_one_token_and_restarts_the_transfer() {
    let mut window = broadcast();
    let first = token(window.feed(0x7E8, &FIRST).unwrap());
    window.feed(0x7E8, &CONSECUTIVE_1).unwrap();
    let second = token(window.feed(0x7E8, &FIRST).unwrap());
    assert_eq!(first.data(), second.data());
    // The old transfer is gone: the new one starts at sequence 1.
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_1).unwrap(),
        FeedOutcome::Pending
    );
    assert!(matches!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap(),
        FeedOutcome::Complete { .. }
    ));
    // After a completed transfer a new first frame starts a new one.
    token(window.feed(0x7E8, &FIRST).unwrap());
    assert_eq!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap_err(),
        Error::WrongSequence
    );
}

#[test]
fn interleaved_replies_from_two_modules_both_complete() {
    let mut window = broadcast();
    assert_eq!(
        token(window.feed(0x7E8, &FIRST).unwrap()).destination_id(),
        0x7E0
    );
    assert_eq!(
        token(window.feed(0x7E9, &FIRST).unwrap()).destination_id(),
        0x7E1
    );
    window.feed(0x7E8, &CONSECUTIVE_1).unwrap();
    window.feed(0x7E9, &CONSECUTIVE_1).unwrap();
    let FeedOutcome::Complete { source, payload } = window.feed(0x7E9, &CONSECUTIVE_2).unwrap()
    else {
        panic!("0x7E9 should be complete");
    };
    assert_eq!((source, payload.len()), (0x7E9, 20));
    let FeedOutcome::Complete { source, payload } = window.feed(0x7E8, &CONSECUTIVE_2).unwrap()
    else {
        panic!("0x7E8 should be complete");
    };
    assert_eq!((source, payload.len()), (0x7E8, 20));
}

#[test]
fn an_error_from_one_module_leaves_the_other_intact() {
    let mut window = broadcast();
    token(window.feed(0x7E8, &FIRST).unwrap());
    token(window.feed(0x7E9, &FIRST).unwrap());
    window.feed(0x7E8, &CONSECUTIVE_1).unwrap();
    // 0x7E9 skips a frame and loses its transfer.
    assert_eq!(
        window.feed(0x7E9, &CONSECUTIVE_2).unwrap_err(),
        Error::WrongSequence
    );
    assert_eq!(
        window.feed(0x7E9, &CONSECUTIVE_1).unwrap_err(),
        Error::UnexpectedFrame
    );
    assert!(matches!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap(),
        FeedOutcome::Complete { source: 0x7E8, .. }
    ));
}

#[test]
fn foreign_traffic_does_not_touch_a_transfer_in_progress() {
    let mut window = engine();
    token(window.feed(0x7E8, &FIRST).unwrap());
    window.feed(0x7E8, &CONSECUTIVE_1).unwrap();
    assert_eq!(
        window.feed(0x7E9, &[0xFF; 8]).unwrap(),
        FeedOutcome::Ignored
    );
    assert!(matches!(
        window.feed(0x7E8, &CONSECUTIVE_2).unwrap(),
        FeedOutcome::Complete { .. }
    ));
}

proptest! {
    #[test]
    fn a_token_is_always_a_continue_to_send_to_a_module_request_id(
        source in prop_oneof![0x7D0..0x800_u32, any::<u32>()],
        bytes in proptest::collection::vec(any::<u8>(), 0..12),
        broadcast_window in any::<bool>(),
    ) {
        let mut window = if broadcast_window { broadcast() } else { engine() };
        if let Ok(FeedOutcome::SendFlowControl(token)) = window.feed(source, &bytes) {
            prop_assert_ne!(token.destination_id(), 0x7DF);
            prop_assert!((0x7E0..=0x7E7).contains(&token.destination_id()));
            prop_assert_eq!(token.destination_id(), source - 8);
            prop_assert!(!token.is_29_bit());
            // 0x30 is continue-to-send; wait is 0x31 and overflow 0x32.
            prop_assert_eq!(token.data()[0], 0x30);
            prop_assert_eq!(token.data().len(), 3);
        }
    }

    #[test]
    fn a_window_never_panics_on_any_sequence_of_frames(
        frames in proptest::collection::vec(
            (
                prop_oneof![0x7E6..0x7F1_u32, any::<u32>()],
                proptest::collection::vec(any::<u8>(), 0..12),
            ),
            0..40,
        ),
    ) {
        for mut window in [broadcast(), engine(), gateway(), unknown_reply()] {
            for (source, bytes) in &frames {
                let _ = window.feed(*source, bytes);
            }
        }
    }

    #[test]
    fn only_a_first_frame_mints_a_token(
        source in 0x7E8..=0x7EF_u32,
        bytes in proptest::collection::vec(any::<u8>(), 0..10),
    ) {
        let minted = matches!(
            broadcast().feed(source, &bytes),
            Ok(FeedOutcome::SendFlowControl(_))
        );
        if minted {
            prop_assert_eq!(bytes[0] >> 4, 1);
        }
    }

    #[test]
    fn an_unknown_reply_window_never_mints_a_token_or_errors(
        source in any::<u32>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..12),
    ) {
        let outcome = unknown_reply().feed(source, &bytes);
        let fine = matches!(
            outcome,
            Ok(FeedOutcome::Ignored
                | FeedOutcome::Complete { .. }
                | FeedOutcome::NoFlowControl { .. })
        );
        prop_assert!(fine, "{:?}", outcome);
    }
}
