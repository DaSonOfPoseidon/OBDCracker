//! Bringing a `gs_usb` controller up: negotiate with the device, check the bitrate listening, and
//! only then go active. See `docs/gsusb.md#connecting`.

use std::time::{Duration, Instant};

use super::can_port::GsUsbPort;
use super::timing;
use super::usb::Usb;
use super::wire::{self, BtConst, DeviceConfig};
use super::{BitrateCheck, BitrateSource, Mode, Options, Session};
use crate::Error;
pub(super) use crate::raw::ConnectFailure;
use crate::raw::port::{CanPort, Filter, PortEvent};
use crate::raw::{BITRATES, RawCan};

/// The longest listen window accepted: a bus that is up shows frames in well under a second.
pub(super) const MAX_LISTEN_WINDOW: Duration = Duration::from_secs(60);

/// Refuses options that can't be right, before anything is sent: a bitrate that no car's
/// diagnostic bus uses, or a listen window too long to be one.
pub(super) fn check_options(options: &Options) -> Result<(), ConnectFailure> {
    if !BITRATES.contains(&options.bitrate) {
        return Err(ConnectFailure::before_device(format!(
            "{} bit/s isn't a diagnostic CAN bitrate: use 250000 or 500000",
            options.bitrate
        )));
    }
    if options.listen_window > MAX_LISTEN_WINDOW {
        return Err(ConnectFailure::before_device(format!(
            "a listen window of {:?} is over the limit of {MAX_LISTEN_WINDOW:?}",
            options.listen_window
        )));
    }
    Ok(())
}

/// Brings the device up, reset on any failure.
pub(super) fn connect<U: Usb>(usb: U, options: &Options) -> Result<Session<U>, ConnectFailure> {
    check_options(options)?;
    let mut port = GsUsbPort::new(usb, options.mode == Mode::ListenOnly);
    match bring_up(&mut port, options) {
        Ok(check) => Ok(Session {
            can: RawCan::new(port),
            mode: options.mode,
            bitrate: options.bitrate,
            check,
        }),
        Err(mut error) => {
            // Whatever was started comes off the bus, and a reset that fails is part of the story.
            if let Err(reset) = port.close() {
                error = Error::Adapter(format!(
                    "{error}; resetting the controller failed too: {reset}"
                ));
            }
            Err(ConnectFailure {
                error,
                events: port.take_events(),
            })
        }
    }
}

fn bring_up<U: Usb>(port: &mut GsUsbPort<U>, options: &Options) -> Result<BitrateCheck, Error> {
    port.control_out(
        "HOST_FORMAT",
        wire::BREQ_HOST_FORMAT,
        wire::VALUE_HOST_FORMAT,
        &wire::host_format(),
    )?;
    let config = port.control_in(
        "DEVICE_CONFIG",
        wire::BREQ_DEVICE_CONFIG,
        wire::VALUE_HOST_FORMAT,
        u16::try_from(wire::DEVICE_CONFIG_LEN).unwrap_or(u16::MAX),
    )?;
    let config = DeviceConfig::parse(&config).map_err(Error::Adapter)?;
    let limits = port.control_in(
        "BT_CONST",
        wire::BREQ_BT_CONST,
        wire::CHANNEL,
        u16::try_from(wire::BT_CONST_LEN).unwrap_or(u16::MAX),
    )?;
    let limits = BtConst::parse(&limits).map_err(Error::Adapter)?;
    port.status(format!(
        "gs_usb device: {} channel(s), firmware {}, hardware {}; using channel 0",
        config.channels, config.sw_version, config.hw_version
    ));
    if limits.feature & wire::FEATURE_LISTEN_ONLY == 0 {
        return Err(Error::Adapter(
            "the device can't do listen-only mode, which this backend needs to check the bitrate \
             before it goes on the bus"
                .to_owned(),
        ));
    }
    if limits.feature & wire::FEATURE_USB_QUIRK_LPC546XX != 0 {
        return Err(Error::Adapter(
            "the device needs the LPC546xx USB quirk (padded packets), which isn't supported"
                .to_owned(),
        ));
    }
    // Before the controller is touched: a bitrate it can't give exactly is never approximated.
    let timing = timing::compute(options.bitrate, &limits).map_err(Error::Adapter)?;
    let berr = limits.feature & wire::FEATURE_BERR_REPORTING != 0;
    let timing_text = format!(
        "BITTIMING {} bit/s: brp {}, prop {}, phase1 {}, phase2 {}, sjw {}",
        options.bitrate,
        timing.brp,
        timing.prop_seg,
        timing.phase_seg1,
        timing.phase_seg2,
        timing.sjw
    );
    // Whatever an earlier program left running comes off the bus before anything else happens.
    port.reset_controller()?;
    port.drain_usb()?;
    port.control_out(
        &timing_text,
        wire::BREQ_BITTIMING,
        wire::CHANNEL,
        &timing.to_bytes(),
    )?;
    if options.mode == Mode::ListenOnly {
        port.start(false, berr)?;
        return Ok(BitrateCheck::NotChecked);
    }
    port.start(false, berr)?;
    let heard = listen(port, options.listen_window);
    // The controller is in reset again before anything else, whatever was heard, and what it
    // heard can't be taken for a reply to a request.
    let reset = port.reset_controller();
    let drained = port.drain_usb();
    let heard = heard?;
    reset?;
    drained?;
    let check = judge(heard, options, port)?;
    port.control_out(
        &timing_text,
        wire::BREQ_BITTIMING,
        wire::CHANNEL,
        &timing.to_bytes(),
    )?;
    port.start(true, berr)?;
    Ok(check)
}

enum Heard {
    Frames,
    Silence,
    Faults(Vec<&'static str>),
}

// Listens at the configured bitrate for the window. Any frame the controller could decode counts,
// whoever sent it.
fn listen<U: Usb>(port: &mut GsUsbPort<U>, window: Duration) -> Result<Heard, Error> {
    port.set_filters(&[
        Filter {
            id: 0,
            mask: 0,
            extended: false,
        },
        Filter {
            id: 0,
            mask: 0,
            extended: true,
        },
    ])?;
    let deadline = Instant::now() + window;
    let mut frames = false;
    let mut faults = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match port.read(left) {
            // An overrun means more frames than the host could read: the bus is busy at this rate.
            Ok(PortEvent::Frame(_) | PortEvent::Overrun) => frames = true,
            Ok(PortEvent::BusOff) => faults.push("bus-off"),
            Ok(PortEvent::ErrorPassive) => faults.push("error-passive"),
            Ok(PortEvent::ErrorFrame) => faults.push("an error frame"),
            Err(Error::Timeout) => break,
            Err(e) => return Err(e),
        }
        if !faults.is_empty() || left.is_zero() {
            break;
        }
    }
    // Nothing is delivered to the transport until it asks for a request's replies.
    port.set_filters(&[])?;
    Ok(if !faults.is_empty() {
        Heard::Faults(faults)
    } else if frames {
        Heard::Frames
    } else {
        Heard::Silence
    })
}

// Decides from what the listen window heard. The OBD port is silent behind a gateway until
// someone asks, so silence alone proves nothing: it passes only when the bitrate was chosen by
// the user or the vehicle profile, and the controller's own latch stops one that gets no ACK.
fn judge<U: Usb>(
    heard: Heard,
    options: &Options,
    port: &mut GsUsbPort<U>,
) -> Result<BitrateCheck, Error> {
    let bitrate = options.bitrate;
    match heard {
        Heard::Faults(faults) => Err(Error::Adapter(format!(
            "heard {} while listening at {bitrate} bit/s: the car's bus isn't at that bitrate, or \
             it is faulted. Not going on the bus",
            faults.join(" and ")
        ))),
        Heard::Frames => Ok(BitrateCheck::Confirmed),
        Heard::Silence => match options.bitrate_source {
            BitrateSource::Configured => {
                port.status(format!(
                    "heard no frames in {:?} at {bitrate} bit/s, so the bitrate is not confirmed; \
                     going active at the configured rate",
                    options.listen_window
                ));
                Ok(BitrateCheck::Unconfirmed)
            }
            BitrateSource::Assumed => Err(Error::Adapter(format!(
                "heard no frames in {:?} at {bitrate} bit/s, and no bitrate was chosen, so it \
                 can't be told whether the car's bus runs at that rate. Say which with --bitrate \
                 or a vehicle profile, or switch the ignition on so the bus is awake",
                options.listen_window
            ))),
        },
    }
}
