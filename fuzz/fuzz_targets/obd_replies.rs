//! Every OBD-II decoder, and reply matching, on arbitrary replies: they return errors and never
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use obdcracker_core::{obd, response, vin};

fuzz_target!(|data: &[u8]| {
    // The first byte splits the input into a request and a reply, for reply matching.
    if let [split, rest @ ..] = data {
        let (request, reply) = rest.split_at(usize::from(*split).min(rest.len()));
        let _ = response::answers(request, reply);
        let _ = response::answers_after_pending(request, reply);
        // The request's own bytes stand in for the PID and frame the caller asked for.
        if let [_, pid, frame, ..] = request {
            let _ = obd::decode_freeze_frame(reply, *pid, *frame);
            let _ = obd::decode_supported_monitor_ids(reply, *pid);
        }
    }
    if let Ok(readings) = obd::decode_current_data(data) {
        readings.for_each(drop);
    }
    for decode in [
        obd::decode_stored_dtcs,
        obd::decode_pending_dtcs,
        obd::decode_permanent_dtcs,
    ] {
        if let Ok(dtcs) = decode(data) {
            dtcs.for_each(|dtc| drop(dtc.to_string()));
        }
    }
    if let Ok(status) = obd::decode_monitor_status(data) {
        status.monitors().for_each(drop);
    }
    let _ = obd::decode_supported_info(data);
    let _ = obd::decode_vin(data);
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(vin) = vin::decode(text)
    {
        let _ = (vin.model_years(), vin.check_digit().status());
    }
    if let Ok(calids) = obd::decode_calids(data) {
        calids.for_each(drop);
    }
    if let Ok(cvns) = obd::decode_cvns(data) {
        cvns.for_each(|cvn| drop(cvn.to_string()));
    }
    let _ = obd::decode_ecu_name(data);
});
