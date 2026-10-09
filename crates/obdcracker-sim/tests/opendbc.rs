//! Real VW/Audi engine and transmission identification replies from opendbc (issue #15), decoded
//! through the same path `fingerprint` uses. They catch the quirks made-up fixture values don't,
//! such as space-padded part numbers.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::uds::{self, did};
use obdcracker_safety::{Approved, Policy};
use obdcracker_transport::fingerprint::{DidValue, IDENTIFICATION_DIDS, UdsModule, fingerprint};
use obdcracker_transport::{Error, Response, Timing, Transport};
use serde::Deserialize;

// Answers each request as it's sent, from the request's CAN ID and payload.
struct Scripted<F> {
    answer: F,
    replies: VecDeque<Response>,
}

impl<F: FnMut(u32, &[u8]) -> Option<Response>> Transport for Scripted<F> {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.replies
            .extend((self.answer)(request.target().can_id(), request.payload()));
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}

#[derive(Deserialize)]
struct Replies {
    reply: Vec<Reply>,
}

#[derive(Deserialize)]
struct Reply {
    car: String,
    ecu: String,
    request_id: u32,
    data: String,
}

impl Reply {
    // The whole reply, service ID included.
    fn payload(&self) -> Vec<u8> {
        let mut payload = vec![0x62];
        payload.extend(
            self.data
                .split(' ')
                .map(|byte| u8::from_str_radix(byte, 16).unwrap()),
        );
        payload
    }
}

fn replies() -> Vec<Reply> {
    let replies: Replies = toml::from_str(include_str!("../fixtures/opendbc-vag.toml")).unwrap();
    assert!(!replies.reply.is_empty());
    replies.reply
}

// VAG's lengths for the two DIDs opendbc asks engines and transmissions for.
const VAG_LAYOUT: [(u16, usize); 2] = [(did::SPARE_PART_NUMBER, 11), (did::SOFTWARE_VERSION, 4)];

// A single-DID reply, as `fingerprint` asks for, with the data opendbc's multi-DID reply had.
fn single(did: u16, data: &[u8]) -> Vec<u8> {
    let mut reply = vec![0x62];
    reply.extend(did.to_be_bytes());
    reply.extend(data);
    reply
}

#[test]
fn multi_did_replies_split_with_vag_lengths() {
    for reply in replies() {
        let what = format!("{} {} {}", reply.car, reply.ecu, reply.data);
        let payload = reply.payload();
        let values: Vec<_> = uds::decode_dids(&payload, &VAG_LAYOUT)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        let [(_, part), (_, version)] = values[..] else {
            panic!("{what}: {values:?}");
        };
        let part = uds::decode_text(part).unwrap();
        let version = uds::decode_text(version).unwrap();
        // A VAG part number: 9 to 11 letters and digits, padding removed.
        assert!(
            (9..=11).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{what}: {part:?}"
        );
        assert!(
            version.len() == 4 && version.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{what}: {version:?}"
        );
    }
}

#[test]
fn space_padded_part_numbers_are_trimmed() {
    let padded: Vec<_> = replies()
        .into_iter()
        .filter(|r| r.payload()[3..14].ends_with(b" "))
        .collect();
    assert!(!padded.is_empty());
    for reply in padded {
        let payload = reply.payload();
        let text = uds::decode_text(&payload[3..14]).unwrap();
        assert!(!text.ends_with(' '), "{}: {text:?}", reply.data);
        assert_eq!(text, String::from_utf8_lossy(&payload[3..14]).trim_end());
    }
}

#[test]
fn a_whole_multi_did_reply_isnt_one_dids_text() {
    // Asked for F187 alone, a module that answered with F189 appended would be misread as a
    // part number containing F1 89; the text check refuses it.
    let payload = replies()[0].payload();
    let data = uds::decode_did(&payload, did::SPARE_PART_NUMBER).unwrap();
    assert!(uds::decode_text(data).is_err());
}

#[test]
fn fingerprint_reads_real_part_numbers() {
    for reply in replies() {
        let payload = reply.payload();
        let module = match reply.ecu.as_str() {
            "engine" => UdsModule::obd_engine(),
            "transmission" => UdsModule::obd_transmission(),
            other => panic!("{other}"),
        };
        assert_eq!(module.request_id, reply.request_id);
        // No ECU answers the mode 09 broadcasts. The module answers F187 and F189, and refuses
        // the rest (request out of range).
        let response_id = module.response_id;
        let request_id = module.request_id;
        let mut car = Scripted {
            answer: |id: u32, request: &[u8]| {
                let [0x22, high, low] = *request else {
                    return None;
                };
                assert_eq!(id, request_id);
                let payload = match u16::from_be_bytes([high, low]) {
                    did::SPARE_PART_NUMBER => single(did::SPARE_PART_NUMBER, &payload[3..14]),
                    did::SOFTWARE_VERSION => single(did::SOFTWARE_VERSION, &payload[16..20]),
                    _ => vec![0x7F, 0x22, 0x31],
                };
                Some(Response {
                    source: response_id,
                    payload,
                })
            },
            replies: VecDeque::new(),
        };
        let timing = Timing {
            p2: Duration::from_millis(5),
            ..Timing::default()
        };
        let got = fingerprint(&mut car, &Policy::read_only(), &[module], timing).unwrap();
        let ids = &got.modules[0].dids;
        let part = ids[0].1.as_ref().unwrap();
        let version = ids[2].1.as_ref().unwrap();
        let text =
            |bytes: &[u8]| DidValue::Text(String::from_utf8_lossy(bytes).trim_end().to_owned());
        assert_eq!(part, &text(&payload[3..14]), "{}", reply.data);
        assert_eq!(version, &text(&payload[16..20]), "{}", reply.data);
        assert_eq!(got.ecus, []);
        assert_eq!(
            ids.iter().map(|&(did, _)| did).collect::<Vec<_>>(),
            IDENTIFICATION_DIDS
        );
        assert!(ids[1].1.is_err() && ids[3].1.is_err() && ids[4].1.is_err());
    }
}
