// One simulated module: answers requests the way a UDS ECU with optional OBD-II support does.

use std::collections::BTreeMap;

use obdcracker_core::response::Nrc;

use crate::fixture::DtcService;

/// A module's diagnostic session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    /// The session a module starts in.
    Default,
    /// The extended diagnostic session, which unlocks more reads.
    Extended,
}

/// A way to make a module misbehave, for testing code that reads its replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Never answer.
    Silent,
    /// Cut every reply to this many bytes. `Truncate(0)` drops replies, like `Silent`.
    Truncate(usize),
    /// Change every reply's first byte so it answers another service.
    WrongSid,
}

#[derive(Debug, Default)]
pub(crate) struct Obd {
    // Mode 01 PID → data bytes. Bitmap PIDs are computed from these.
    pub(crate) pids: BTreeMap<u8, Vec<u8>>,
    // Mode 09 PID → item count and data bytes.
    pub(crate) info: BTreeMap<u8, (u8, Vec<u8>)>,
    pub(crate) dtcs: Vec<u16>,
}

#[derive(Debug)]
pub(crate) struct Did {
    pub(crate) id: u16,
    pub(crate) data: Vec<u8>,
    pub(crate) extended_only: bool,
    // How many response-pending replies come before the answer.
    pub(crate) pending: u8,
}

/// One simulated module.
#[derive(Debug)]
pub struct Ecu {
    pub(crate) name: String,
    pub(crate) request_id: u32,
    pub(crate) response_id: u32,
    pub(crate) obd: Option<Obd>,
    pub(crate) dids: Vec<Did>,
    pub(crate) dtc: DtcService,
    pub(crate) session: Session,
    pub(crate) fault: Option<Fault>,
}

const NEGATIVE: u8 = 0x7F;
const POSITIVE_OFFSET: u8 = 0x40;
// P2 50 ms, P2* 5000 ms (in 10 ms units), as ISO 14229-2 defaults.
const SESSION_TIMING: [u8; 4] = [0x00, 0x32, 0x01, 0xF4];
const SUPPRESS_POSITIVE: u8 = 0x80;

fn negative(sid: u8, nrc: Nrc) -> Vec<u8> {
    vec![NEGATIVE, sid, nrc.code()]
}

fn one(reply: Vec<u8>) -> Vec<Vec<u8>> {
    vec![reply]
}

impl Ecu {
    /// The module's name in the profile, such as `engine`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The module's current diagnostic session.
    #[must_use]
    pub fn session(&self) -> Session {
        self.session
    }

    /// Makes the module misbehave from now on, or behave again with `None`.
    pub fn set_fault(&mut self, fault: Option<Fault>) {
        self.fault = fault;
    }

    pub(crate) fn has_obd(&self) -> bool {
        self.obd.is_some()
    }

    // Every reply to `request`, in order, after any fault is applied.
    pub(crate) fn answer(&mut self, request: &[u8], functional: bool) -> Vec<Vec<u8>> {
        let mut replies = self.handle(request, functional);
        // ISO 14229-1: a functionally addressed request gets no "not supported" or "out of
        // range" refusal; the module stays silent instead.
        if functional {
            replies.retain(|reply| {
                !matches!(
                    reply.as_slice(),
                    [0x7F, _, 0x11 | 0x12 | 0x31 | 0x7E | 0x7F]
                )
            });
        }
        match self.fault {
            None => {}
            Some(Fault::Silent) => replies.clear(),
            Some(Fault::Truncate(len)) => replies.iter_mut().for_each(|r| r.truncate(len)),
            Some(Fault::WrongSid) => replies.iter_mut().for_each(|r| {
                if let Some(sid) = r.first_mut() {
                    *sid = sid.wrapping_add(1);
                }
            }),
        }
        replies.retain(|r| !r.is_empty());
        replies
    }

    fn handle(&mut self, request: &[u8], functional: bool) -> Vec<Vec<u8>> {
        let Some((&sid, data)) = request.split_first() else {
            return Vec::new();
        };
        match sid {
            0x01 | 0x03 | 0x09 => match &self.obd {
                Some(obd) => obd.answer(sid, data).into_iter().collect(),
                // A module without OBD-II stays out of broadcast requests.
                None if functional => Vec::new(),
                None => one(negative(sid, Nrc::ServiceNotSupported)),
            },
            0x10 => self.session_control(data),
            0x19 => self.read_dtc_information(data),
            0x22 => self.read_dids(data),
            0x3E => tester_present(data),
            _ => one(negative(sid, Nrc::ServiceNotSupported)),
        }
    }

    fn session_control(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let &[sub] = data else {
            return one(negative(0x10, Nrc::IncorrectMessageLength));
        };
        let session = sub & !SUPPRESS_POSITIVE;
        self.session = match session {
            0x01 => Session::Default,
            0x03 => Session::Extended,
            _ => return one(negative(0x10, Nrc::SubFunctionNotSupported)),
        };
        if sub & SUPPRESS_POSITIVE != 0 {
            return Vec::new();
        }
        let mut reply = vec![0x50, session];
        reply.extend(SESSION_TIMING);
        one(reply)
    }

    fn read_dtc_information(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let Some((&raw, args)) = data.split_first() else {
            return one(negative(0x19, Nrc::IncorrectMessageLength));
        };
        let sub = raw & !SUPPRESS_POSITIVE;
        let mask = match (sub, args) {
            (0x01 | 0x02, &[mask]) => mask,
            (0x0A, []) => 0xFF,
            (0x01 | 0x02 | 0x0A, _) => return one(negative(0x19, Nrc::IncorrectMessageLength)),
            _ => return one(negative(0x19, Nrc::SubFunctionNotSupported)),
        };
        if !self.dtc.reports.contains(&sub) {
            return one(negative(0x19, Nrc::SubFunctionNotSupported));
        }
        if raw & SUPPRESS_POSITIVE != 0 {
            return Vec::new();
        }
        let availability = self.dtc.availability;
        let matching = self
            .dtc
            .dtcs
            .iter()
            .filter(|&&(_, status)| sub == 0x0A || status & availability & mask != 0);
        let mut reply = vec![0x59, sub, availability];
        if sub == 0x01 {
            // The fixture holds at most u16::MAX DTCs
            let count = u16::try_from(matching.count()).unwrap_or(u16::MAX);
            reply.push(self.dtc.format);
            reply.extend(count.to_be_bytes());
        } else {
            for &(code, status) in matching {
                reply.extend(&code.to_be_bytes()[1..]);
                reply.push(status);
            }
        }
        one(reply)
    }

    fn read_dids(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let (ids, partial) = data.as_chunks::<2>();
        if ids.is_empty() || !partial.is_empty() {
            return one(negative(0x22, Nrc::IncorrectMessageLength));
        }
        let mut reply = vec![0x22 + POSITIVE_OFFSET];
        let mut pending = 0;
        let mut found = false;
        for &id in ids {
            let id = u16::from_be_bytes(id);
            let readable = self.dids.iter().find(|did| {
                did.id == id && (!did.extended_only || self.session == Session::Extended)
            });
            if let Some(did) = readable {
                found = true;
                pending = pending.max(did.pending);
                reply.extend(id.to_be_bytes());
                reply.extend(&did.data);
            }
        }
        // ISO 14229-1: unsupported DIDs are left out; if none is supported, the request is refused.
        if !found {
            return one(negative(0x22, Nrc::RequestOutOfRange));
        }
        let mut replies = vec![negative(0x22, Nrc::ResponsePending); usize::from(pending)];
        replies.push(reply);
        replies
    }
}

fn tester_present(data: &[u8]) -> Vec<Vec<u8>> {
    match *data {
        [0x00] => one(vec![0x7E, 0x00]),
        [SUPPRESS_POSITIVE] => Vec::new(),
        [_] => one(negative(0x3E, Nrc::SubFunctionNotSupported)),
        _ => one(negative(0x3E, Nrc::IncorrectMessageLength)),
    }
}

impl Obd {
    // OBD-II modules don't answer what they don't support, so this is None then.
    fn answer(&self, sid: u8, data: &[u8]) -> Option<Vec<u8>> {
        let mut reply = vec![sid + POSITIVE_OFFSET];
        match (sid, data) {
            (0x01, pids) if (1..=6).contains(&pids.len()) => {
                for &pid in pids {
                    if let Some(bitmap) = self.pid_bitmap(pid) {
                        reply.push(pid);
                        reply.extend(bitmap);
                    } else if let Some(value) = self.pids.get(&pid) {
                        reply.push(pid);
                        reply.extend(value);
                    }
                }
            }
            (0x03, []) => {
                // build() caps the list at 255 codes
                reply.push(u8::try_from(self.dtcs.len()).unwrap_or(u8::MAX));
                for dtc in &self.dtcs {
                    reply.extend(dtc.to_be_bytes());
                }
            }
            (0x09, [0x00]) => {
                let bits = bitmap(0x00, self.info.keys().copied(), false);
                if bits == 0 {
                    return None;
                }
                reply.push(0x00);
                reply.extend(bits.to_be_bytes());
            }
            (0x09, &[pid]) => {
                let (count, data) = self.info.get(&pid)?;
                reply.extend([pid, *count]);
                reply.extend(data);
            }
            _ => return None,
        }
        (reply.len() > 1).then_some(reply)
    }

    // The 4 data bytes of a mode 01 bitmap PID (0x00, 0x20, …), if the module supports it:
    // 0x00 whenever it has any PID, a later one when it has a PID above it.
    fn pid_bitmap(&self, pid: u8) -> Option<[u8; 4]> {
        if !pid.is_multiple_of(0x20) || !self.pids.keys().any(|&p| pid == 0 || p > pid) {
            return None;
        }
        let more = self
            .pids
            .keys()
            .any(|&p| u16::from(p) > u16::from(pid) + 0x20);
        Some(bitmap(pid, self.pids.keys().copied(), more).to_be_bytes())
    }
}

// Bit 31 is PID base+1 and bit 0 is base+0x20; `next` sets bit 0 for the next bitmap PID.
fn bitmap(base: u8, pids: impl Iterator<Item = u8>, next: bool) -> u32 {
    let mut bits = u32::from(next);
    for pid in pids {
        if let Some(offset @ 1..=31) = pid.checked_sub(base) {
            bits |= 1 << (32 - u32::from(offset));
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use obdcracker_profile::Profile;

    use crate::SimBus;

    // The policy sends UDS only to physical IDs today, so this calls the module directly.
    #[test]
    fn functional_uds_requests_get_no_not_supported_refusals() {
        let coding = "[[ecu]]\nmodule = \"engine\"\n[[ecu.did]]\nid = 0x0600\n\
                      hex = \"01 02 03 04 05 06 07 08 09 0A\"\nsession = \"extended\"\n";
        let mut bus = SimBus::new(&Profile::builtin("a7").unwrap(), coding).unwrap();
        let engine = bus.ecu_mut("engine").unwrap();
        // ISO 14229-1: a functionally addressed request gets no NRC 0x11, 0x12, 0x31, 0x7E or
        // 0x7F. The coding DID 0x0600 needs the extended session.
        for request in [
            &[0x22, 0x12, 0x34][..],
            &[0x19, 0x04, 0x00, 0x00, 0x00, 0xFF],
            &[0x10, 0x05],
            &[0x22, 0x06, 0x00],
            &[0x2E, 0x06, 0x00, 0x01],
        ] {
            assert_eq!(
                engine.answer(request, true),
                Vec::<Vec<u8>>::new(),
                "{request:02X?}"
            );
            assert_eq!(engine.answer(request, false).len(), 1, "{request:02X?}");
        }
        // Other refusals are still sent.
        assert_eq!(engine.answer(&[0x19, 0x02], true), [[0x7F, 0x19, 0x13]]);
    }
}
