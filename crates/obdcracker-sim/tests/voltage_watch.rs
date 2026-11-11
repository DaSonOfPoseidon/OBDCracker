//! Long reads that stop when the battery goes flat: `sweep_dids` and `discover_with` re-check the
//! supply voltage every so many requests, on the simulated car, and leave any extended session.

use std::num::NonZeroUsize;

use obdcracker_profile::Profile;
use obdcracker_safety::{Policy, SupplyVoltage};
use obdcracker_sim::{Session, SimBus};
use obdcracker_transport::discover::{DiscoverOptions, discover_with};
use obdcracker_transport::fingerprint::UdsModule;
use obdcracker_transport::sweep::{Stop, Sweep, SweepOptions, Why, sweep_dids};
use obdcracker_transport::voltage::{LowVoltage, VoltageWatch};
use obdcracker_transport::{Error, S3, Timing, Transport};

const FIRST: u16 = 0xF180;

fn known(millivolts: u32) -> SupplyVoltage {
    SupplyVoltage::Known { millivolts }
}

// The engine with 0xF181 and 0xF185 answering in the default session; everything else in range
// is refused as out of range.
fn car() -> SimBus {
    let fixture = "[[ecu]]\nmodule = \"engine\"\n\
                   [[ecu.did]]\nid = 0xF181\nhex = \"AA\"\n\
                   [[ecu.did]]\nid = 0xF185\nhex = \"BB\"\n";
    SimBus::new(&Profile::builtin("a7").unwrap(), fixture).unwrap()
}

fn watching(interval: usize) -> SweepOptions {
    let mut options = SweepOptions::default();
    options.voltage_watch = Some(VoltageWatch::every(NonZeroUsize::new(interval).unwrap()));
    options
}

fn sweep(bus: &mut SimBus, count: u16, options: &SweepOptions) -> Sweep {
    sweep_dids(
        bus,
        &Policy::read_only(),
        &UdsModule::obd_engine(),
        FIRST..=FIRST + (count - 1),
        Timing::default(),
        options,
    )
    .unwrap()
}

fn low(after: usize, millivolts: u32) -> Stop {
    Stop {
        at: FIRST + u16::try_from(after).unwrap(),
        why: Why::LowVoltage(LowVoltage { after, millivolts }),
    }
}

fn reads(bus: &SimBus) -> usize {
    bus.sent().iter().filter(|r| r.payload()[0] == 0x22).count()
}

#[test]
fn a_sweep_with_no_watch_goes_on_whatever_the_voltage() {
    let mut bus = car();
    bus.drop_supply_voltage_after(0, known(9_000));
    let got = sweep(&mut bus, 120, &SweepOptions::default());
    assert_eq!(got.stop, None);
    assert_eq!(reads(&bus), 120);
}

#[test]
fn a_drop_on_the_request_that_is_checked_stops_before_the_next_and_keeps_what_was_found() {
    let mut bus = car();
    bus.drop_supply_voltage_after(50, known(11_000));
    let got = sweep(&mut bus, 200, &watching(50));
    assert_eq!(got.stop, Some(low(50, 11_000)));
    assert_eq!(reads(&bus), 50);
    assert_eq!(
        got.found,
        [(0xF181, Ok(vec![0xAA])), (0xF185, Ok(vec![0xBB]))]
    );
    assert!(!got.out_of_step);
}

#[test]
fn a_drop_one_request_later_is_seen_at_the_next_check() {
    let mut bus = car();
    bus.drop_supply_voltage_after(51, known(11_000));
    let got = sweep(&mut bus, 200, &watching(50));
    assert_eq!(got.stop, Some(low(100, 11_000)));
    assert_eq!(reads(&bus), 100);
}

#[test]
fn a_drop_before_the_last_request_stops_it_and_a_run_no_longer_than_the_interval_isnt_checked() {
    let mut bus = car();
    bus.drop_supply_voltage_after(50, known(11_000));
    let got = sweep(&mut bus, 51, &watching(50));
    assert_eq!(got.stop, Some(low(50, 11_000)));
    assert_eq!(reads(&bus), 50);

    let mut bus = car();
    bus.drop_supply_voltage_after(0, known(11_000));
    let got = sweep(&mut bus, 50, &watching(50));
    assert_eq!(got.stop, None);
    assert_eq!(reads(&bus), 50);
}

#[test]
fn an_interval_of_one_checks_before_every_request_but_the_first() {
    let mut bus = car();
    bus.drop_supply_voltage_after(3, known(11_000));
    let got = sweep(&mut bus, 10, &watching(1));
    assert_eq!(got.stop, Some(low(3, 11_000)));
    assert_eq!(reads(&bus), 3);
}

#[test]
fn a_voltage_that_is_unknown_or_fine_doesnt_stop_the_sweep() {
    for supply in [SupplyVoltage::Unknown, known(12_600), known(11_800)] {
        let mut bus = car();
        bus.drop_supply_voltage_after(10, supply);
        let got = sweep(&mut bus, 120, &watching(10));
        assert_eq!(got.stop, None, "{supply:?}");
        assert_eq!(reads(&bus), 120);
    }
}

#[test]
fn a_millivolt_under_the_refusal_threshold_stops_it() {
    let mut bus = car();
    bus.drop_supply_voltage_after(10, known(11_799));
    let got = sweep(&mut bus, 120, &watching(10));
    assert_eq!(got.stop, Some(low(10, 11_799)));
}

#[test]
fn the_watch_can_use_other_thresholds() {
    let mut bus = car();
    bus.drop_supply_voltage_after(10, known(11_900));
    let mut options = watching(10);
    if let Some(watch) = &mut options.voltage_watch {
        watch.thresholds.refuse_mv = 12_000;
    }
    assert_eq!(sweep(&mut bus, 120, &options).stop, Some(low(10, 11_900)));
}

#[test]
fn a_stop_in_the_extended_session_leaves_it() {
    let mut bus = car();
    bus.drop_supply_voltage_after(5, known(11_000));
    let mut options = watching(10);
    options.extended = Some(S3::default());
    let got = sweep(&mut bus, 100, &options);
    assert_eq!(got.stop, Some(low(10, 11_000)));
    assert_eq!(got.still_extended, None);
    assert!(!got.out_of_step);
    assert_eq!(bus.ecu("engine").unwrap().session(), Session::Default);
    let payloads: Vec<Vec<u8>> = bus.sent().iter().map(|r| r.payload().to_vec()).collect();
    assert_eq!(payloads.first(), Some(&vec![0x10, 0x03]));
    assert_eq!(payloads.last(), Some(&vec![0x10, 0x01]));
    assert_eq!(reads(&bus), 10);
}

// Where the sweep stopped is where to go on from: the rest reads the same as one run would have.
#[test]
fn going_on_from_where_it_stopped_finds_the_rest() {
    let mut bus = car();
    bus.drop_supply_voltage_after(20, known(11_000));
    let first = sweep(&mut bus, 30, &watching(10));
    let Some(Stop { at, .. }) = first.stop else {
        panic!("it didn't stop");
    };
    bus.set_supply_voltage(known(12_600));
    let rest = sweep_dids(
        &mut bus,
        &Policy::read_only(),
        &UdsModule::obd_engine(),
        at..=FIRST + 29,
        Timing::default(),
        &watching(10),
    )
    .unwrap();
    assert_eq!(rest.stop, None);
    let all: Vec<u16> = first
        .found
        .iter()
        .chain(&rest.found)
        .map(|(did, _)| *did)
        .collect();
    assert_eq!(all, [0xF181, 0xF185]);
    assert_eq!(at, FIRST + 20);
}

#[test]
fn the_stop_says_what_it_read() {
    let stop = Why::LowVoltage(LowVoltage {
        after: 50,
        millivolts: 11_500,
    });
    assert_eq!(
        stop.to_string(),
        "the supply voltage fell to 11.5 V after 50 requests"
    );
}

// A profile whose gateway answers at 0x710, the 17th candidate in the range 0x700 to 0x769.
fn discovery() -> (Profile, SimBus) {
    let profile = Profile::from_toml(
        "name = \"x\"\nbitrate = 500000\n\
         [[module]]\nname = \"gateway\"\nrequest_id = 0x710\nresponse_id = 0x77A\nprotocol = \"uds\"\n\
         [discovery]\nfirst_request_id = 0x700\nlast_request_id = 0x769\nreply_offset = 0x6A\n",
    )
    .unwrap();
    let fixture =
        "[[ecu]]\nmodule = \"gateway\"\n[[ecu.did]]\nid = 0xF187\ntext = \"4G0907468AD\"\n";
    let bus = SimBus::new(&profile, fixture).unwrap();
    (profile, bus)
}

fn discover_watched(
    profile: &Profile,
    bus: &mut SimBus,
    interval: usize,
) -> obdcracker_transport::discover::Discovered {
    let mut options = DiscoverOptions::default();
    options.voltage_watch = Some(VoltageWatch::every(NonZeroUsize::new(interval).unwrap()));
    let policy = profile.narrow_for_discovery(Policy::read_only()).unwrap();
    discover_with(
        bus,
        &policy,
        &profile.candidates(),
        Timing::default(),
        &options,
    )
    .unwrap()
}

#[test]
fn discovery_with_no_watch_reads_every_candidate() {
    let (profile, mut bus) = discovery();
    bus.drop_supply_voltage_after(0, known(9_000));
    let policy = profile.narrow_for_discovery(Policy::read_only()).unwrap();
    let got = discover_with(
        &mut bus,
        &policy,
        &profile.candidates(),
        Timing::default(),
        &DiscoverOptions::default(),
    )
    .unwrap();
    assert_eq!(got.low_voltage, None);
    assert_eq!(bus.sent().len(), profile.candidates().len());
    assert_eq!(got.found.len(), 1);
}

#[test]
fn discovery_stops_at_the_first_check_after_a_drop_and_keeps_what_answered() {
    let (profile, mut bus) = discovery();
    bus.drop_supply_voltage_after(20, known(11_000));
    let got = discover_watched(&profile, &mut bus, 20);
    assert_eq!(
        got.low_voltage,
        Some(LowVoltage {
            after: 20,
            millivolts: 11_000
        })
    );
    assert_eq!(bus.sent().len(), 20);
    assert_eq!(got.found.len(), 1);
    assert_eq!(got.found[0].request_id, 0x710);
}

#[test]
fn discovery_with_a_drop_before_the_gateway_is_asked_stops_without_it() {
    let (profile, mut bus) = discovery();
    bus.drop_supply_voltage_after(5, known(11_000));
    let got = discover_watched(&profile, &mut bus, 5);
    assert_eq!(
        got.low_voltage,
        Some(LowVoltage {
            after: 5,
            millivolts: 11_000
        })
    );
    assert_eq!(got.found, []);
}

#[test]
fn discovery_carries_on_when_the_voltage_is_unknown_or_fine() {
    for supply in [SupplyVoltage::Unknown, known(12_000)] {
        let (profile, mut bus) = discovery();
        bus.drop_supply_voltage_after(5, supply);
        let got = discover_watched(&profile, &mut bus, 5);
        assert_eq!(got.low_voltage, None, "{supply:?}");
        assert_eq!(bus.sent().len(), profile.candidates().len());
    }
}

#[test]
fn a_patient_discovery_with_a_watch_reports_how_long_it_waited_and_still_stops() {
    let (profile, mut bus) = discovery();
    bus.drop_supply_voltage_after(20, known(11_000));
    let mut options = DiscoverOptions::default();
    options.patient = Some(std::time::Duration::from_secs(5));
    options.voltage_watch = Some(VoltageWatch::every(NonZeroUsize::new(20).unwrap()));
    let policy = profile.narrow_for_discovery(Policy::read_only()).unwrap();
    let got = discover_with(
        &mut bus,
        &policy,
        &profile.candidates(),
        Timing::default(),
        &options,
    )
    .unwrap();
    assert_eq!(got.waited, Some(std::time::Duration::from_secs(5)));
    assert!(got.low_voltage.is_some());
    assert_eq!(bus.sent().len(), 20);
}

// A voltage the adapter failed to give counts as unknown: the sweep's own reads decide what an
// adapter that can't be trusted does next.
struct FailsToMeasure(SimBus);

impl Transport for FailsToMeasure {
    fn send(&mut self, request: &obdcracker_safety::Approved) -> Result<(), Error> {
        self.0.send(request)
    }

    fn recv(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<obdcracker_transport::Response, Error> {
        self.0.recv(timeout)
    }

    fn supply_voltage(&mut self) -> Result<SupplyVoltage, Error> {
        Err(Error::Adapter("no answer to ATRV".to_owned()))
    }
}

#[test]
fn a_voltage_that_cant_be_read_doesnt_stop_the_sweep() {
    let mut bus = FailsToMeasure(car());
    let got = sweep_dids(
        &mut bus,
        &Policy::read_only(),
        &UdsModule::obd_engine(),
        FIRST..=FIRST + 119,
        Timing::default(),
        &watching(10),
    )
    .unwrap();
    assert_eq!(got.stop, None);
    assert_eq!(bus.0.sent().len(), 120);
}
