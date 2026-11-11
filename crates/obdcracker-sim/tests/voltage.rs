//! The simulated car's battery: a default, one that is set, and one that drops mid-run.

use std::time::Duration;

use obdcracker_core::obd;
use obdcracker_safety::{Policy, Protocol, SupplyVoltage, Target};
use obdcracker_sim::SimBus;
use obdcracker_transport::Transport;

fn known(millivolts: u32) -> SupplyVoltage {
    SupplyVoltage::Known { millivolts }
}

fn ask(car: &mut SimBus) {
    let vin = Policy::read_only()
        .approve(
            Protocol::Uds,
            Target::ObdFunctional,
            &obd::vehicle_info(0x02),
        )
        .unwrap();
    car.send(&vin).unwrap();
    while car.recv(Duration::from_millis(5)).is_ok() {}
}

#[test]
fn a_new_car_has_a_good_battery() {
    let mut car = SimBus::builtin("a7").unwrap();
    assert_eq!(car.supply_voltage().unwrap(), known(12_600));
}

#[test]
fn the_voltage_can_be_set_and_made_unknown() {
    let mut car = SimBus::builtin("a7").unwrap();
    car.set_supply_voltage(known(11_500));
    assert_eq!(car.supply_voltage().unwrap(), known(11_500));
    car.set_supply_voltage(SupplyVoltage::Unknown);
    assert_eq!(car.supply_voltage().unwrap(), SupplyVoltage::Unknown);
}

#[test]
fn reading_the_voltage_sends_nothing() {
    let mut car = SimBus::builtin("a7").unwrap();
    car.supply_voltage().unwrap();
    assert_eq!(car.sent(), []);
}

#[test]
fn the_voltage_drops_once_that_many_requests_have_been_sent() {
    let mut car = SimBus::builtin("a7").unwrap();
    car.drop_supply_voltage_after(2, known(11_000));
    assert_eq!(car.supply_voltage().unwrap(), known(12_600));
    ask(&mut car);
    assert_eq!(car.supply_voltage().unwrap(), known(12_600));
    ask(&mut car);
    assert_eq!(car.supply_voltage().unwrap(), known(11_000));
    ask(&mut car);
    assert_eq!(car.supply_voltage().unwrap(), known(11_000));
}

#[test]
fn a_drop_after_zero_requests_is_there_from_the_start() {
    let mut car = SimBus::builtin("a7").unwrap();
    car.drop_supply_voltage_after(0, known(10_000));
    assert_eq!(car.supply_voltage().unwrap(), known(10_000));
}

#[test]
fn the_drop_replaces_a_set_voltage_and_setting_one_again_ends_it() {
    let mut car = SimBus::builtin("a7").unwrap();
    car.set_supply_voltage(known(12_400));
    car.drop_supply_voltage_after(1, SupplyVoltage::Unknown);
    ask(&mut car);
    assert_eq!(car.supply_voltage().unwrap(), SupplyVoltage::Unknown);
    car.set_supply_voltage(known(13_000));
    assert_eq!(car.supply_voltage().unwrap(), known(13_000));
}
