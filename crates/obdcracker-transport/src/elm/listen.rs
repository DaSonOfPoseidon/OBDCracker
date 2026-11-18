// Listening to the bus through the adapter's monitor, sending nothing (docs/elm327.md#listen-only-monitor).

use std::time::{Duration, Instant};

use super::codec::{Event, Line, Status};
use super::{
    Elm, INTERRUPT, LONGEST_WAIT, MONITOR_ACK_ELM, MONITOR_ACK_STN, MONITOR_ELM, MONITOR_STN,
    RAW_OFF, RAW_ON,
};
use crate::link::Link;
use crate::{Error, Heard, Listen, ListenEnd, ListenFilter, OnFrame};

impl<L: Link> Listen for Elm<L> {
    // In this order, and nothing else is written until the monitor is stopped:
    //   1. the silent setting, which must answer `OK`, or nothing after it is sent;
    //   2. the settings that make the monitor print every frame as it is on the wire
    //      (`AT CAF0`, and `AT CFC0` so the adapter can't answer a first frame it hears);
    //   3. the receive filter;
    //   4. the monitor command, which prints until the host writes one byte, `X`.
    // Afterwards the driver is as `send` expects it, except for the receive filter, which the
    // cache knows (`filter`) and the next request sets for itself.
    fn listen(
        &mut self,
        filter: &ListenFilter,
        wait: Duration,
        on_frame: OnFrame<'_>,
    ) -> Result<ListenEnd, Error> {
        // Before anything is written, as in `send`.
        self.trusted()?;
        // A request still running, or a TP2.0 channel's monitor, is finished first.
        self.ready()?;
        self.silence_monitor()?;
        self.set_up_listen(filter)?;
        self.start_monitor()?;
        // The adapter prints no prompt until it is stopped, as for a request.
        self.busy = true;
        let outcome = self.hear_frames(wait, on_frame);
        self.finish_listen(outcome)
    }
}

impl<L: Link> Elm<L> {
    // The first step: the monitor must not acknowledge the frames it hears. A clone that ignores
    // the setting would be a node on the bus, so a refusal ends the driver (`guarded_command`).
    // On a fresh connection this is also the command that shows whether the adapter echoes each
    // character as it reads it, which the mode switches below need: it is a setting, and
    // nothing in it reaches the bus.
    fn silence_monitor(&mut self) -> Result<(), Error> {
        let command = self.monitor_ack_command(false);
        let needs_echo = || {
            Error::Adapter(format!(
                "a listen needs an adapter that echoes each character as it reads it (such as an \
                 OBDLink), and this one doesn't ({command} was sent as a setting, and nothing \
                 else)"
            ))
        };
        if self.early_echo == Some(false) {
            return Err(needs_echo());
        }
        let lines = self.checked_answer(command)?;
        if !lines.iter().map(String::as_str).eq(["OK"]) {
            return Err(self.break_down(self.refusal(command, &lines)));
        }
        if self.early_echo == Some(true) {
            Ok(())
        } else {
            Err(needs_echo())
        }
    }

    // The monitor prints each frame whole and as it is on the bus: no ISO-TP formatting to hide
    // the PCI byte, and no automatic flow control for a first frame it hears (the same switches
    // as for a TP2.0 channel, without that mode's acknowledgement). A mode the driver is
    // already in is left. The monitor's width and filter are set last.
    fn set_up_listen(&mut self, filter: &ListenFilter) -> Result<(), Error> {
        // A request sent in segments left `AT CAF0` on, which `AT CAF1` below would undo behind
        // the driver's back.
        if self.segmenting {
            self.guarded_command("ATCAF1")?;
            self.segmenting = false;
            self.sync_adaptive()?;
        }
        self.set_width(filter.is_29_bit())?;
        if !self.raw {
            for command in RAW_ON {
                self.guarded_command(command)?;
            }
            // From here `finish_listen` puts them back.
            self.raw = true;
            self.sync_adaptive()?;
        }
        let pattern = filter.as_str();
        if self.filter != pattern {
            self.expect_ok(&format!("ATCRA{pattern}"))?;
            pattern.clone_into(&mut self.filter);
        }
        Ok(())
    }

    // Hands each frame the monitor prints to `on_frame` until the deadline, the callback stops,
    // or something is wrong. The monitor is still running when this returns.
    fn hear_frames(&mut self, wait: Duration, on_frame: OnFrame<'_>) -> Result<ListenEnd, Error> {
        let started = Instant::now();
        let deadline = started + wait.min(LONGEST_WAIT);
        loop {
            // A monitor can stay quiet for as long as the caller waits, so only the caller's
            // deadline bounds it.
            let Some(event) = self.next_event(deadline)? else {
                return Ok(ListenEnd::Deadline);
            };
            match event {
                // A monitor prints none until the driver stops it.
                Event::Prompt => {
                    return Err(self.break_down("the adapter stopped monitoring on its own".into()));
                }
                Event::Overlong => {
                    return Err(self.break_down("the adapter printed an overlong line".into()));
                }
                Event::Line(text) => match self.reply_line(&text)? {
                    // The command's echo.
                    None => {}
                    Some(Line::Frame(frame)) => {
                        let heard = Heard::new(
                            started.elapsed(),
                            frame.id(),
                            frame.is_29_bit(),
                            frame.data().to_vec(),
                        );
                        if on_frame(&heard)?.is_break() {
                            return Ok(ListenEnd::Stopped);
                        }
                    }
                    Some(Line::Status(Status::BufferFull)) => {
                        return Err(Error::Adapter(
                            "the adapter said BUFFER FULL while monitoring: its link is too slow \
                             for the frames, and some were lost; narrow the filter or use a \
                             faster baud rate"
                                .into(),
                        ));
                    }
                    // One frame the adapter couldn't read: kept for the audit log.
                    Some(Line::Status(Status::DataError | Status::RxError)) => {
                        self.hear(&text);
                    }
                    Some(Line::Status(status)) if status.is_failure() => {
                        return Err(Error::Adapter(format!("the adapter said {status}")));
                    }
                    Some(_) => {
                        self.hear(&text);
                    }
                },
            }
            // After every line, so a bus full of frames can't outlast the caller's wait.
            if Instant::now() >= deadline {
                return Ok(ListenEnd::Deadline);
            }
        }
    }

    // Stops the monitor and puts the driver back as `send` expects it, however the listen ended.
    // A broken driver writes nothing more.
    fn finish_listen(&mut self, outcome: Result<ListenEnd, Error>) -> Result<ListenEnd, Error> {
        if self.broken.is_some() {
            return outcome;
        }
        let stopped = self.interrupt();
        let restored = if self.broken.is_none() && self.raw {
            self.switch_raw(false)
        } else {
            Ok(())
        };
        let end = outcome?;
        stopped?;
        restored?;
        Ok(end)
    }
}

/// The adapter commands a [`Listen::listen`] writes on a connection that has not been used yet,
/// in order, for an STN (`stn`) or a plain ELM327: the silent setting, the modes that print
/// frames whole, the width and filter, the monitor, then the commands that put the modes back
/// once the monitor has been stopped with `X` (written once, between the two). A connection
/// that has already set some of them skips those, and an STN on a fast link also gets
/// `AT AT0`/`AT AT1` around the modes. None reaches the bus.
#[must_use]
pub fn listen_commands(stn: bool, filter: &ListenFilter) -> Vec<String> {
    let (silent, monitor) = if stn {
        (MONITOR_ACK_STN[1], MONITOR_STN)
    } else {
        (MONITOR_ACK_ELM[1], MONITOR_ELM)
    };
    let mut commands = vec![silent.to_owned()];
    if filter.is_29_bit() {
        commands.push("ATSP7".to_owned());
    }
    commands.extend(RAW_ON.map(str::to_owned));
    commands.push(format!("ATCRA{filter}"));
    commands.push(monitor.to_owned());
    commands.push(String::from_utf8_lossy(INTERRUPT).into_owned());
    commands.extend(RAW_OFF.map(str::to_owned));
    commands.push(silent.to_owned());
    commands
}
