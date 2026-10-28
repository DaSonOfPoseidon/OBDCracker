//! The gateway's installed-module list: what is read, in which order, and what each failure leaves.

use std::collections::VecDeque;
use std::time::Duration;

use obdcracker_core::response::{Error as ReplyError, NegativeResponse, Nrc};
use obdcracker_safety::{Approved, ModuleIds, Policy, Rejection};
use obdcracker_transport::fingerprint::{FingerprintError, ReadError, UdsModule};
use obdcracker_transport::gateway::{GatewayTables, Installed, read_gateway_list};
use obdcracker_transport::{Error, Response, Timing, Transport, hex};

type Answer = Box<dyn FnMut(&[u8]) -> Vec<Response>>;

struct Car {
    answer: Answer,
    replies: VecDeque<Response>,
    sent: Vec<String>,
}

impl Car {
    fn new(answer: impl FnMut(&[u8]) -> Vec<Response> + 'static) -> Self {
        Self {
            answer: Box::new(answer),
            replies: VecDeque::new(),
            sent: Vec::new(),
        }
    }
}

impl Transport for Car {
    fn send(&mut self, request: &Approved) -> Result<(), Error> {
        let id = request.target().can_id();
        self.sent
            .push(format!("{id:03X} {}", hex(request.payload())));
        self.replies.extend((self.answer)(request.payload()));
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Response, Error> {
        self.replies.pop_front().ok_or(Error::Timeout)
    }
}

const TIMING: Timing = Timing {
    p2: Duration::from_millis(5),
    p2_star: Duration::from_millis(5),
    max_pending: 2,
};

// The Audi A7's gateway (0x710), session #124: reads of 2A2A and 2A2C.
const ADDRESSES: &str = "62 2A 2A 01 02 03 03 04 05 06 08 09 0E 10 11 13 8B 34 15 16 17 17 18 19 1B 1E 20 22 28 2E 30 36 3C 3D 3E 42 46 47 52 53 55 56 57 85 5F 62 26 65 69 6C 6D 6F 72 3B 7F 82 84 48 5B 88 89 8A 8D 8F 90 AC 44 81 8E C0 A9 40 51 8C BA 14 00 00 00 00 00 00 00";
const REQUEST_IDS: &str = "62 2A 2C 00 00 00 00 07 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 57 07 56 07 55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 1D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 12 00 00 07 58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

const TABLES: GatewayTables = GatewayTables {
    addresses: 0x2A2A,
    request_ids: Some(0x2A2C),
};

fn bytes(hex: &str) -> Vec<u8> {
    hex.split(' ')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

fn gateway() -> UdsModule {
    UdsModule {
        name: "gateway".into(),
        request_id: 0x710,
        response_id: 0x77A,
    }
}

fn policy() -> Policy {
    Policy::read_only()
        .narrowed_to(&[ModuleIds {
            request: 0x710,
            reply: 0x77A,
        }])
        .unwrap()
}

fn reply(payload: &[u8]) -> Vec<Response> {
    vec![Response {
        source: 0x77A,
        payload: payload.to_vec(),
    }]
}

fn a7_gateway() -> Car {
    Car::new(|request| match request {
        [0x22, 0x2A, 0x2A] => reply(&bytes(ADDRESSES)),
        [0x22, 0x2A, 0x2C] => reply(&bytes(REQUEST_IDS)),
        _ => vec![],
    })
}

#[test]
fn reads_the_a7_gateways_tables_with_two_reads() {
    let mut car = a7_gateway();
    let list = read_gateway_list(&mut car, &policy(), &gateway(), TABLES, TIMING)
        .unwrap()
        .unwrap();
    assert_eq!(car.sent, ["710 22 2A 2A", "710 22 2A 2C"]);
    assert_eq!(list.entries, 80);
    assert_eq!(list.installed.len(), 73);
    assert_eq!(list.request_ids, Ok(()));
    assert!(!list.out_of_step);
    let at = |slot: usize| list.installed.iter().find(|i| i.slot == slot).unwrap();
    assert_eq!(
        *at(2),
        Installed {
            slot: 2,
            address: 0x03,
            request_id: Some(0x0713),
        }
    );
    assert_eq!(at(3).request_id, None);
    // 22 is one of the two request IDs of modules the A7 profile doesn't list.
    assert_eq!((at(24).address, at(24).request_id), (0x22, Some(0x071D)));
    let with_ids = list.installed.iter().filter(|i| i.request_id.is_some());
    assert_eq!(with_ids.count(), 8);
}

#[test]
fn without_a_request_id_table_only_the_addresses_are_read() {
    let mut car = a7_gateway();
    let tables = GatewayTables {
        request_ids: None,
        ..TABLES
    };
    let list = read_gateway_list(&mut car, &policy(), &gateway(), tables, TIMING)
        .unwrap()
        .unwrap();
    assert_eq!(car.sent, ["710 22 2A 2A"]);
    assert!(list.installed.iter().all(|i| i.request_id.is_none()));
    assert_eq!(list.request_ids, Ok(()));
}

#[test]
fn a_failed_address_read_is_an_error_and_asks_nothing_more() {
    let mut silent = Car::new(|_| vec![]);
    let got = read_gateway_list(&mut silent, &policy(), &gateway(), TABLES, TIMING).unwrap();
    assert_eq!(got.err(), Some(ReadError::NoReply));
    assert_eq!(silent.sent, ["710 22 2A 2A"]);

    let mut refusing = Car::new(|_| reply(&[0x7F, 0x22, 0x31]));
    let got = read_gateway_list(&mut refusing, &policy(), &gateway(), TABLES, TIMING).unwrap();
    assert_eq!(
        got.err(),
        Some(ReadError::Reply(ReplyError::Negative(NegativeResponse {
            sid: 0x22,
            nrc: Nrc::RequestOutOfRange,
        })))
    );
    assert_eq!(refusing.sent.len(), 1);
}

#[test]
fn a_failed_request_id_read_keeps_the_addresses_and_says_why() {
    // One byte short: not two per address.
    let mut short = bytes(REQUEST_IDS);
    short.pop();
    let mut car = Car::new(move |request| match request {
        [0x22, 0x2A, 0x2A] => reply(&bytes(ADDRESSES)),
        _ => reply(&short),
    });
    let list = read_gateway_list(&mut car, &policy(), &gateway(), TABLES, TIMING)
        .unwrap()
        .unwrap();
    assert_eq!(list.installed.len(), 73);
    assert!(list.installed.iter().all(|i| i.request_id.is_none()));
    assert!(matches!(
        list.request_ids,
        Err(ReadError::Undecodable {
            error: ReplyError::Malformed,
            ..
        })
    ));
    assert!(!list.out_of_step);
}

#[test]
fn an_unanswered_request_id_read_leaves_the_connection_out_of_step() {
    let mut car = Car::new(|request| match request {
        [0x22, 0x2A, 0x2A] => reply(&bytes(ADDRESSES)),
        _ => vec![],
    });
    let list = read_gateway_list(&mut car, &policy(), &gateway(), TABLES, TIMING)
        .unwrap()
        .unwrap();
    assert_eq!(list.request_ids, Err(ReadError::NoReply));
    assert!(list.out_of_step);
}

#[test]
fn a_policy_refusal_sends_nothing() {
    let mut car = a7_gateway();
    let other = UdsModule {
        request_id: 0x7E0,
        ..gateway()
    };
    let got = read_gateway_list(&mut car, &policy(), &other, TABLES, TIMING);
    assert!(matches!(
        got,
        Err(FingerprintError::Rejected(Rejection::WrongTarget))
    ));
    assert_eq!(car.sent, Vec::<String>::new());
}

mod comparison {
    use obdcracker_transport::gateway::{Installed, ListedAs, Tried, compare};

    fn listed(slot: usize, address: u8) -> Installed {
        Installed {
            slot,
            address,
            request_id: None,
        }
    }

    #[test]
    fn gives_every_listed_address_one_status() {
        let installed = [
            listed(0, 0x01),
            listed(1, 0x13),
            listed(2, 0x05),
            listed(3, 0x71),
        ];
        let profile = [
            (0x01, Tried::Answered),
            (0x13, Tried::Silent),
            (0x05, Tried::NotTried),
            (0x44, Tried::Answered),
        ];
        let statuses: Vec<_> = compare(&installed, &profile)
            .into_iter()
            .map(|c| c.status)
            .collect();
        assert_eq!(
            statuses,
            [
                ListedAs::Found,
                ListedAs::Silent,
                ListedAs::NotTried,
                ListedAs::NotInProfile
            ]
        );
    }

    #[test]
    fn reports_a_duplicate_once_per_slot_and_keeps_the_order() {
        let installed = [listed(2, 0x03), listed(3, 0x03)];
        let got = compare(&installed, &[(0x03, Tried::Silent)]);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].installed.slot, got[1].installed.slot), (2, 3));
        assert!(got.iter().all(|c| c.status == ListedAs::Silent));
    }

    #[test]
    fn an_address_tried_twice_is_found_if_either_try_answered() {
        // A module the ISO-TP pass found silent can answer the TP2.0 pass.
        let profile = [(0x52, Tried::Silent), (0x52, Tried::Answered)];
        let got = compare(&[listed(0, 0x52)], &profile);
        assert_eq!(got[0].status, ListedAs::Found);
        let profile = [(0x52, Tried::NotTried), (0x52, Tried::Silent)];
        let got = compare(&[listed(0, 0x52)], &profile);
        assert_eq!(got[0].status, ListedAs::Silent);
    }

    #[test]
    fn nothing_listed_is_nothing_compared() {
        assert_eq!(compare(&[], &[(0x01, Tried::Answered)]).len(), 0);
    }
}
