//! Positive and negative responses shared by OBD-II on CAN and UDS (ISO 14229-1, ISO 15765-4).

use obdcracker_core::response::{Error, NegativeResponse, Nrc, positive};

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
