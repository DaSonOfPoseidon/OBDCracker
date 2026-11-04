//! Real identification replies from opendbc, decoded through the same path `fingerprint` uses. They
//! catch the quirks made-up fixture values don't, such as space-padded part numbers: VW/Audi
//! engines and transmissions (issue #15), then Hyundai, Ford and Honda modules (issue #12).

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response;
use obdcracker_core::uds::{self, did};
use obdcracker_safety::{Approved, Policy, Protocol, Target};
use obdcracker_transport::fingerprint::{
    DidValue, IDENTIFICATION_DIDS, ReadError, UdsModule, fingerprint,
};
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

#[derive(Deserialize)]
struct OtherReplies {
    reply: Vec<OtherReply>,
}

#[derive(Deserialize)]
struct OtherReply {
    make: String,
    car: String,
    ecu: String,
    request_id: u32,
    response_id: u32,
    payload: String,
}

impl OtherReply {
    fn payload(&self) -> Vec<u8> {
        self.payload
            .split(' ')
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }
}

fn other_replies() -> Vec<OtherReply> {
    let replies: OtherReplies =
        toml::from_str(include_str!("../fixtures/opendbc-other-makes.toml")).unwrap();
    replies.reply
}

// What a reply's identification DID holds, read from the stored value in opendbc's
// `fingerprints.py`.
enum Want {
    // The text, without the padding the decoder removes.
    Text(&'static str),
    // Not printable text: a 0x00 or control byte inside the value. The DID's data as received.
    Binary(&'static [u8]),
}

struct Expected {
    make: &'static str,
    car: &'static str,
    ecu: &'static str,
    request_id: u32,
    response_id: u32,
    did: u16,
    want: Want,
}

const fn expect(
    make: &'static str,
    car: &'static str,
    ecu: &'static str,
    (request_id, response_id): (u32, u32),
    did: u16,
    want: Want,
) -> Expected {
    Expected {
        make,
        car,
        ecu,
        request_id,
        response_id,
        did,
        want,
    }
}

// The DID opendbc asks each make for. Hyundai's stored value starts with the echoed DID, the
// other two hold only the data.
const HYUNDAI: u16 = 0xF100;
const FORD: u16 = did::SOFTWARE_NUMBER;
const HONDA: u16 = 0xF181;

// The fixture's replies, in order, with the IDs opendbc gives each ECU: the reply ID is the
// request ID + 8 on 11 bits, and the request's last two bytes swapped on 29 bits.
use Want::{Binary, Text};

const EXPECTED: [Expected; 20] = [
    expect(
        "hyundai",
        "HYUNDAI_AZERA_6TH_GEN",
        "fwdRadar",
        (0x7D0, 0x7D8),
        HYUNDAI,
        // Nine trailing spaces in opendbc.
        Text("IG__ SCC F-CU-      1.00 1.00 99110-G8100"),
    ),
    expect(
        "hyundai",
        "HYUNDAI_AZERA_6TH_GEN",
        "eps",
        (0x7D4, 0x7DC),
        HYUNDAI,
        Binary(b"IG  MDPS C 1.00 1.02 56310G8510\x00 4IGSC103"),
    ),
    expect(
        "hyundai",
        "HYUNDAI_AZERA_6TH_GEN",
        "fwdCamera",
        (0x7C4, 0x7CC),
        HYUNDAI,
        Text("IG  MFC  AT MES LHD 1.00 1.04 99211-G8100 200511"),
    ),
    expect(
        "hyundai",
        "HYUNDAI_SONATA",
        "abs",
        (0x7D1, 0x7D9),
        HYUNDAI,
        Binary(b"DN ESC \x01 102\x19\x04\x13 58910-L1300"),
    ),
    expect(
        "hyundai",
        "HYUNDAI_SONATA",
        "eps",
        (0x7D4, 0x7DC),
        HYUNDAI,
        Binary(b"DN8 MDPS C 1,00 1,01 56310L0010\x00 4DNAC101"),
    ),
    expect(
        "hyundai",
        "HYUNDAI_GENESIS",
        "fwdCamera",
        (0x7C4, 0x7CC),
        HYUNDAI,
        Text("DH LKAS 1.1 -150210"),
    ),
    expect(
        "ford",
        "FORD_BRONCO_SPORT_MK1",
        "eps",
        (0x730, 0x738),
        FORD,
        Text("LX6C-14D003-AH"),
    ),
    expect(
        "ford",
        "FORD_BRONCO_SPORT_MK1",
        "abs",
        (0x760, 0x768),
        FORD,
        Text("LX6C-2D053-RD"),
    ),
    expect(
        "ford",
        "FORD_BRONCO_SPORT_MK1",
        "fwdCamera",
        (0x706, 0x70E),
        FORD,
        Text("M1PT-14F397-AC"),
    ),
    expect(
        "ford",
        "FORD_ESCAPE_MK4_5",
        "eps",
        (0x730, 0x738),
        FORD,
        Text("PZ11-14D003-EA"),
    ),
    expect(
        "ford",
        "FORD_ESCAPE_MK4_5",
        "fwdCamera",
        (0x706, 0x70E),
        FORD,
        Text("PJ6T-14H102-ABL"),
    ),
    expect(
        "ford",
        "FORD_EXPLORER_MK6",
        "eps",
        (0x730, 0x738),
        FORD,
        Text("L1MC-14D003-AJ"),
    ),
    expect(
        "ford",
        "FORD_EXPLORER_MK6",
        "abs",
        (0x760, 0x768),
        FORD,
        Text("L1MC-2D053-AJ"),
    ),
    expect(
        "honda",
        "HONDA_NBOX_2G",
        "vsa",
        (0x18DA_28F1, 0x18DA_F128),
        HONDA,
        Text("57114-TTA-J030"),
    ),
    expect(
        "honda",
        "HONDA_NBOX_2G",
        "eps",
        (0x18DA_30F1, 0x18DA_F130),
        HONDA,
        Text("39990-TTA-J040"),
    ),
    expect(
        "honda",
        "HONDA_NBOX_2G",
        "srs",
        (0x18DA_53F1, 0x18DA_F153),
        HONDA,
        Text("77959-TTA-N930"),
    ),
    expect(
        "honda",
        "HONDA_ACCORD",
        "transmission",
        (0x18DA_1EF1, 0x18DA_F11E),
        HONDA,
        Text("28101-6A7-A220"),
    ),
    expect(
        "honda",
        "HONDA_ACCORD",
        "vsa",
        (0x18DA_28F1, 0x18DA_F128),
        HONDA,
        Text("57114-TVA-B040"),
    ),
    expect(
        "honda",
        "HONDA_CIVIC",
        "eps",
        (0x18DA_30F1, 0x18DA_F130),
        HONDA,
        Text("39990-TBA-A030"),
    ),
    expect(
        "honda",
        "HONDA_CIVIC",
        "gateway",
        (0x18DA_EFF1, 0x18DA_F1EF),
        HONDA,
        Text("38897-TBA-A010"),
    ),
];

fn paired() -> Vec<(OtherReply, Expected)> {
    let replies = other_replies();
    let expected = EXPECTED;
    assert_eq!(replies.len(), expected.len());
    replies.into_iter().zip(expected).collect()
}

fn of_make(make: &str) -> Vec<(OtherReply, Expected)> {
    paired()
        .into_iter()
        .filter(|(r, _)| r.make == make)
        .collect()
}

#[test]
fn other_makes_fixture_holds_exactly_the_expected_replies() {
    for (reply, want) in paired() {
        let what = format!("{} {} {}", reply.make, reply.car, reply.ecu);
        assert_eq!(
            (&*reply.make, &*reply.car, &*reply.ecu),
            (want.make, want.car, want.ecu),
            "{what}"
        );
        assert_eq!(reply.request_id, want.request_id, "{what}");
        assert_eq!(reply.response_id, want.response_id, "{what}");
    }
}

#[test]
fn other_makes_replies_decode_to_the_stored_text() {
    for (reply, want) in paired() {
        let what = format!("{} {} {}", reply.make, reply.car, reply.ecu);
        let payload = reply.payload();
        let data = uds::decode_did(&payload, want.did).unwrap_or_else(|e| panic!("{what}: {e}"));
        match want.want {
            Want::Text(text) => assert_eq!(uds::decode_text(data), Ok(text), "{what}"),
            // A control byte inside the value is no text to show; fingerprint keeps it as bytes.
            Want::Binary(bytes) => {
                assert_eq!(
                    uds::decode_text(data),
                    Err(response::Error::Malformed),
                    "{what}"
                );
                assert_eq!(data, bytes, "{what}");
            }
        }
    }
}

#[test]
fn other_makes_padding_is_removed_and_nothing_else() {
    let mut padded = 0;
    for (reply, want) in paired() {
        let payload = reply.payload();
        let data = uds::decode_did(&payload, want.did).unwrap();
        let Want::Text(text) = want.want else {
            continue;
        };
        // The stored value is the text, then spaces (Hyundai) or 0x00 (Ford, Honda).
        assert!(data.starts_with(text.as_bytes()), "{text}");
        let padding = &data[text.len()..];
        padded += usize::from(!padding.is_empty());
        assert!(padding.iter().all(|&b| b == 0 || b == b' '), "{text}");
        assert!(!text.ends_with([' ', '\0']), "{text}");
    }
    // Every Ford and Honda value, and Hyundai's radar.
    assert_eq!(padded, 15);
}

#[test]
fn fingerprint_reads_real_ford_software_numbers() {
    let fords = of_make("ford");
    assert_eq!(fords.len(), 7);
    for (reply, want) in fords {
        let Want::Text(text) = want.want else {
            panic!("{}", reply.car);
        };
        let payload = reply.payload();
        let module = UdsModule {
            name: reply.ecu.clone(),
            request_id: reply.request_id,
            response_id: reply.response_id,
        };
        let (request_id, response_id) = (module.request_id, module.response_id);
        let mut car = Scripted {
            answer: |id: u32, request: &[u8]| {
                // Nothing answers the mode 09 broadcasts.
                let [0x22, high, low] = *request else {
                    return None;
                };
                assert_eq!(id, request_id);
                // The module answers its software number and refuses the other DIDs.
                let payload = if u16::from_be_bytes([high, low]) == FORD {
                    payload.clone()
                } else {
                    vec![0x7F, 0x22, 0x31]
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
        assert_eq!(
            ids.iter().map(|&(did, _)| did).collect::<Vec<_>>(),
            IDENTIFICATION_DIDS
        );
        for (did, value) in ids {
            if *did == FORD {
                assert_eq!(value, &Ok(DidValue::Text(text.to_owned())), "{}", reply.car);
            } else {
                assert!(matches!(value, Err(ReadError::Reply(_))), "{did:04X}");
            }
        }
        assert_eq!(got.ecus, []);
    }
}

#[test]
fn honda_29_bit_reads_are_approved_with_the_swapped_reply_id() {
    let hondas = of_make("honda");
    assert_eq!(hondas.len(), 7);
    let policy = Policy::read_only();
    for (reply, want) in hondas {
        let approved = policy
            .approve(
                Protocol::Uds,
                Target::physical(reply.request_id),
                &uds::read_did(HONDA),
            )
            .unwrap_or_else(|e| panic!("{} {}: {e:?}", reply.car, reply.ecu));
        assert_eq!(approved.target(), Target::Physical29(reply.request_id));
        assert!(approved.target().is_29_bit());
        // The policy works the reply ID out itself; opendbc's rule gives the same one.
        assert_eq!(approved.reply_id(), Some(want.response_id));
    }
}

// Records each request and refuses every DID.
struct Refuser {
    response_id: u32,
    sent: Vec<(Target, Vec<u8>)>,
    replies: VecDeque<Response>,
}

impl Transport for Refuser {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        self.sent
            .push((request.target(), request.payload().to_vec()));
        if request.payload().first() == Some(&0x22) {
            self.replies.push_back(Response {
                source: self.response_id,
                payload: vec![0x7F, 0x22, 0x31],
            });
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}

#[test]
fn fingerprint_addresses_a_honda_module_at_its_29_bit_id() {
    // Honda's own DID (F181) isn't one of IDENTIFICATION_DIDS, so a fingerprint asks a Honda for
    // the five standard ones; this checks they go to the module's 29-bit ID.
    let reply = other_replies()
        .into_iter()
        .find(|r| r.car == "HONDA_NBOX_2G" && r.ecu == "vsa")
        .unwrap();
    assert_eq!(reply.request_id, 0x18DA_28F1);
    let mut car = Refuser {
        response_id: reply.response_id,
        sent: Vec::new(),
        replies: VecDeque::new(),
    };
    let module = UdsModule {
        name: reply.ecu,
        request_id: reply.request_id,
        response_id: reply.response_id,
    };
    let timing = Timing {
        p2: Duration::from_millis(5),
        ..Timing::default()
    };
    let got = fingerprint(&mut car, &Policy::read_only(), &[module], timing).unwrap();
    let reads: Vec<_> = car
        .sent
        .iter()
        .filter(|(_, payload)| payload[0] == 0x22)
        .collect();
    assert_eq!(reads.len(), IDENTIFICATION_DIDS.len());
    for (target, _) in reads {
        assert_eq!(*target, Target::Physical29(0x18DA_28F1));
    }
    assert!(got.modules[0].dids.iter().all(|(_, v)| v.is_err()));
}
