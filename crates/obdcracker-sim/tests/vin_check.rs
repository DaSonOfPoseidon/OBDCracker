//! The VIN check against a profile, on simulated cars with one, two or no VIN.

use obdcracker_profile::Profile;
use obdcracker_safety::Policy;
use obdcracker_sim::SimBus;
use obdcracker_transport::fingerprint::{VinCheck, check_vin};
use obdcracker_transport::{Audited, Timing};

const A7_VIN: &str = "WAU2MBFC6EN093415";

fn check(fixture: &str) -> VinCheck {
    let profile = Profile::builtin("a7").unwrap();
    let mut car = SimBus::new(&profile, fixture).unwrap();
    check_vin(&mut car, &Policy::read_only(), Timing::default(), &profile).unwrap()
}

fn engine(vin: &str) -> String {
    format!("[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\nvin = \"{vin}\"\n")
}

fn transmission(vin: &str) -> String {
    format!("[[ecu]]\nmodule = \"transmission\"\n[ecu.obd]\nvin = \"{vin}\"\n")
}

#[test]
fn the_shipped_a7_is_the_car_its_profile_fits() {
    let profile = Profile::builtin("a7").unwrap();
    let mut car = SimBus::builtin("a7").unwrap();
    let got = check_vin(&mut car, &Policy::read_only(), Timing::default(), &profile).unwrap();
    assert_eq!(
        got,
        VinCheck::Match {
            vin: A7_VIN.to_owned()
        }
    );
    assert_eq!(car.sent().len(), 1);
}

#[test]
fn another_makes_vin_is_a_mismatch() {
    assert_eq!(
        check(&engine("4T1BF1FK5EU123456")),
        VinCheck::Mismatch {
            vin: "4T1BF1FK5EU123456".to_owned()
        }
    );
}

#[test]
fn an_audi_outside_the_years_is_a_mismatch() {
    // Position 10 'V' is 1997 or 2027.
    let vin = "WAU2MBFC6VN093415";
    assert_eq!(
        check(&engine(vin)),
        VinCheck::Mismatch {
            vin: vin.to_owned()
        }
    );
}

#[test]
fn two_ecus_with_one_vin_match() {
    let fixture = format!("{}{}", engine(A7_VIN), transmission(A7_VIN));
    assert!(matches!(check(&fixture), VinCheck::Match { .. }));
}

#[test]
fn two_ecus_with_two_vins_conflict() {
    let fixture = format!("{}{}", engine(A7_VIN), transmission("WAU2MBFC6EN093416"));
    assert_eq!(
        check(&fixture),
        VinCheck::Conflicting {
            vins: vec![A7_VIN.to_owned(), "WAU2MBFC6EN093416".to_owned()]
        }
    );
}

#[test]
fn an_ecu_that_has_no_vin_gives_no_vin() {
    assert_eq!(
        check(
            "[[ecu]]\nmodule = \"engine\"\n[ecu.obd]\necu_name = { acronym = \"ECM\", name = \"EngineControl\" }\n"
        ),
        VinCheck::NoVin
    );
}

#[test]
fn a_car_that_answers_nothing_gives_no_vin() {
    assert_eq!(check("[[ecu]]\nmodule = \"gateway\"\n"), VinCheck::NoVin);
}

#[test]
fn the_audit_log_sees_the_request_before_the_reply() {
    let profile = Profile::builtin("a7").unwrap();
    let path =
        std::env::temp_dir().join(format!("obdcracker-vin-check-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let car = SimBus::builtin("a7").unwrap();
    let mut audited = Audited::open(&path, car, "sim").unwrap();
    check_vin(
        &mut audited,
        &Policy::read_only(),
        Timing::default(),
        &profile,
    )
    .unwrap();
    let log = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<_> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(
        lines[0].ends_with(r#""dir":"tx","id":"7DF","payload":"09 02","link":"sim"}"#),
        "{log}"
    );
    assert!(lines[1].contains(r#""dir":"rx","id":"7E8""#), "{log}");
    std::fs::remove_file(path).unwrap();
}
