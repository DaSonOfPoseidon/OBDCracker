//! Positive and negative responses shared by OBD-II on CAN and UDS (ISO 14229-1, ISO 15765-4).

use obdcracker_core::response::{Error, NegativeResponse, Nrc, answers, positive};

#[test]
fn positive_reply_returns_the_bytes_after_the_service_id() {
    // 0x22 F190 answered with 0x62 F190 and data
    assert_eq!(
        positive(0x22, &[0x62, 0xF1, 0x90, 0x57]),
        Ok(&[0xF1, 0x90, 0x57][..])
    );
    // OBD-II mode 09 answered with 0x49
    assert_eq!(positive(0x09, &[0x49, 0x02]), Ok(&[0x02][..]));
}

#[test]
fn negative_reply_decodes_the_code() {
    assert_eq!(
        positive(0x22, &[0x7F, 0x22, 0x31]),
        Err(Error::Negative(NegativeResponse {
            sid: 0x22,
            nrc: Nrc::RequestOutOfRange
        }))
    );
}

#[test]
fn response_pending_is_flagged_so_callers_keep_waiting() {
    let Err(Error::Negative(nr)) = positive(0x19, &[0x7F, 0x19, 0x78]) else {
        panic!("expected a negative response");
    };
    assert!(nr.nrc.is_pending());
    assert!(!Nrc::ConditionsNotCorrect.is_pending());
}

#[test]
fn every_code_round_trips_and_unknown_codes_are_kept() {
    for code in 0..=u8::MAX {
        assert_eq!(Nrc::from(code).code(), code);
    }
    assert_eq!(Nrc::from(0x10), Nrc::GeneralReject);
    assert_eq!(Nrc::from(0x7F), Nrc::ServiceNotSupportedInActiveSession);
    assert_eq!(Nrc::from(0x99), Nrc::Other(0x99));
}

#[test]
fn codes_display_their_meaning() {
    assert_eq!(
        Nrc::SecurityAccessDenied.to_string(),
        "security access denied (0x33)"
    );
    assert_eq!(Nrc::Other(0x99).to_string(), "negative response code 0x99");
}

#[test]
fn rejects_replies_for_another_service_or_too_short() {
    assert_eq!(
        positive(0x22, &[0x59, 0x02]),
        Err(Error::WrongService(0x59))
    );
    assert_eq!(
        positive(0x22, &[0x7F, 0x19, 0x31]),
        Err(Error::WrongService(0x7F))
    );
    assert_eq!(positive(0x22, &[]), Err(Error::TooShort));
    assert_eq!(positive(0x22, &[0x7F, 0x22]), Err(Error::TooShort));
}

#[test]
fn negative_reply_is_exactly_three_bytes() {
    // A trailing byte must not pass as a valid response-pending
    assert_eq!(
        positive(0x19, &[0x7F, 0x19, 0x78, 0xAA]),
        Err(Error::Malformed)
    );
}

#[test]
fn codec_errors_work_with_the_question_mark_operator() {
    fn decode() -> Result<(), Box<dyn std::error::Error>> {
        positive(0x22, &[0x7F, 0x22, 0x33])?;
        Ok(())
    }
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        obdcracker_core::isotp::Frame::parse(&[], obdcracker_core::isotp::Addressing::Normal)?;
        Ok(())
    }
    assert_eq!(
        decode().unwrap_err().to_string(),
        "service 0x22 refused: security access denied (0x33)"
    );
    assert!(parse().is_err());
}

#[test]
fn answers_matches_the_echoed_obd_pid() {
    let vin = [0x09, 0x02];
    assert!(answers(&vin, b"\x49\x02\x01WAUZZZ4G1EN000000"));
    // A late reply to a PID 04 request uses the same service.
    assert!(!answers(&vin, &[0x49, 0x04, 0x01, 0x41]));
    assert!(!answers(&vin, &[0x49]));
    // Mode 01 leaves out unsupported PIDs, so the first echoed PID is any requested one.
    assert!(answers(&[0x01, 0x0C, 0x0D], &[0x41, 0x0D, 0x00]));
    assert!(!answers(&[0x01, 0x0C, 0x0D], &[0x41, 0x05, 0x82]));
    // Mode 03 echoes nothing.
    assert!(answers(&[0x03], &[0x43, 0x00]));
}

#[test]
fn answers_matches_the_echoed_did_or_subfunction() {
    let read = [0x22, 0xF1, 0x89, 0xF1, 0x87];
    assert!(answers(&read, &[0x62, 0xF1, 0x87, 0x30]));
    assert!(!answers(&read, &[0x62, 0xF1, 0x90, 0x57]));
    assert!(!answers(&read, &[0x62, 0xF1]));
    assert!(answers(&[0x19, 0x02, 0x08], &[0x59, 0x02, 0xFF]));
    assert!(!answers(
        &[0x19, 0x02, 0x08],
        &[0x59, 0x01, 0xFF, 0x00, 0x00, 0x01]
    ));
    // A request with the suppress bit (bit 7, any subfunction service) gets no positive reply,
    // so any positive reply is a late answer to an earlier, unsuppressed request. Refusals still
    // answer it.
    for (request, positive) in [
        (&[0x10, 0x83][..], &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4][..]),
        (&[0x19, 0x82, 0x08], &[0x59, 0x02, 0xFF]),
        (&[0x3E, 0x80], &[0x7E, 0x00]),
    ] {
        assert!(!answers(request, positive), "{request:02X?}");
        assert!(
            answers(request, &[0x7F, request[0], 0x12]),
            "{request:02X?}"
        );
    }
    assert!(answers(
        &[0x10, 0x03],
        &[0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]
    ));
    assert!(!answers(
        &[0x10, 0x03],
        &[0x50, 0x01, 0x00, 0x32, 0x01, 0xF4]
    ));
    assert!(answers(&[0x3E, 0x00], &[0x7E, 0x00]));
}

#[test]
fn answers_takes_any_refusal_of_the_service() {
    // A negative reply doesn't echo the DID, so it can only be matched by service.
    assert!(answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x22, 0x31]));
    assert!(answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x22, 0x78]));
    assert!(!answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x19, 0x78]));
    assert!(!answers(&[0x22, 0xF1, 0x90], &[0x7F, 0x22]));
    assert!(!answers(&[0x22, 0xF1, 0x90], &[0x59, 0x02]));
    assert!(!answers(&[0x22, 0xF1, 0x90], &[]));
    assert!(!answers(&[], &[0x62, 0xF1, 0x90]));
}
