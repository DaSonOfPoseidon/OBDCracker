//! Reading a VAG gateway's list of installed modules. Reads only.
//!
//! See docs/scanning.md#gateway-list.

use obdcracker_core::uds;
use obdcracker_safety::{Policy, Protocol, Target};

use crate::fingerprint::{FingerprintError, ReadError, UdsModule, ask};
use crate::{Timing, Transport};

/// The DIDs of a gateway's installed-module tables, from the vehicle profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayTables {
    /// The table of one VAG address per slot (0 = empty slot).
    pub addresses: u16,
    /// The table of two bytes of request CAN ID per slot (0 = none), if the car has one.
    pub request_ids: Option<u16>,
}

/// One module the gateway lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// Its slot in the tables.
    pub slot: usize,
    /// Its VAG address. An address the gateway lists twice is two entries.
    pub address: u8,
    /// The CAN ID requests go to, if the request ID table gave one for this slot.
    pub request_id: Option<u16>,
}

/// What [`read_gateway_list`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayList {
    /// How many slots the address table has, empty ones included.
    pub entries: usize,
    /// The modules listed, in slot order.
    pub installed: Vec<Installed>,
    /// `Err` if the request ID table was asked for and couldn't be read, so every
    /// [`Installed::request_id`] is `None`. A request ID in a slot with no address is dropped.
    pub request_ids: Result<(), ReadError>,
    /// The request ID read went unanswered, so its reply may still arrive as the answer to the
    /// connection's next request.
    pub out_of_step: bool,
}

/// Reads the address table of `module`'s installed-module list (`22 <addresses>`), then its request
/// ID table (`22 <request_ids>`) if `tables` has one. Both requests are approved before the first
/// is sent.
///
/// A table that can't be read or decoded loses only itself: the address table is the outer
/// `Err`, and a request ID table that failed is [`GatewayList::request_ids`]. Nothing is asked
/// after an address read that failed, since its late reply could pass for the next one's.
///
/// # Errors
///
/// [`FingerprintError::Rejected`] if the policy refuses either request (nothing is sent), or
/// [`FingerprintError::Transport`] if the adapter fails.
pub fn read_gateway_list<T: Transport + ?Sized>(
    transport: &mut T,
    policy: &Policy,
    module: &UdsModule,
    tables: GatewayTables,
    timing: Timing,
) -> Result<Result<GatewayList, ReadError>, FingerprintError> {
    let target = Target::physical(module.request_id);
    let approve = |did: u16| {
        policy
            .approve(Protocol::Uds, target, &uds::read_did(did))
            .map_err(FingerprintError::Rejected)
    };
    let address_request = approve(tables.addresses)?;
    let id_request = tables
        .request_ids
        .map(|did| Ok((did, approve(did)?)))
        .transpose()?;

    let addresses = ask(
        transport,
        &address_request,
        module.response_id,
        timing,
        |reply| {
            let table = uds::decode_gateway_addresses(reply, tables.addresses)?;
            Ok((table.entries(), table.installed().collect::<Vec<_>>()))
        },
    )?;
    let (entries, listed) = match addresses {
        Ok(read) => read,
        Err(e) => return Ok(Err(e)),
    };
    let mut installed: Vec<Installed> = listed
        .into_iter()
        .map(|(slot, address)| Installed {
            slot,
            address,
            request_id: None,
        })
        .collect();

    let mut request_ids = Ok(());
    let mut out_of_step = false;
    if let Some((did, request)) = id_request {
        let read = ask(transport, &request, module.response_id, timing, |reply| {
            let table = uds::decode_gateway_request_ids(reply, did, entries)?;
            Ok(table.installed().collect::<Vec<_>>())
        })?;
        match read {
            Ok(ids) => {
                for (slot, id) in ids {
                    if let Some(entry) = installed.iter_mut().find(|i| i.slot == slot) {
                        entry.request_id = Some(id);
                    }
                }
            }
            Err(e) => {
                out_of_step = matches!(e, ReadError::NoReply | ReadError::StillPending);
                request_ids = Err(e);
            }
        }
    }
    Ok(Ok(GatewayList {
        entries,
        installed,
        request_ids,
        out_of_step,
    }))
}

/// What a scan did about an address the profile knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tried {
    /// The scan read it and it answered, a refusal included.
    Answered,
    /// The scan asked and nothing answered.
    Silent,
    /// The scan didn't ask, such as for a module that isn't plain UDS.
    NotTried,
}

/// How a listed module compares with what the scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedAs {
    /// A profile module with this address answered.
    Found,
    /// A profile module with this address was tried and stayed silent.
    Silent,
    /// A profile module has this address but the scan didn't try it.
    NotTried,
    /// No profile module has this address.
    NotInProfile,
}

/// One listed module and how it compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compared {
    /// The gateway's entry.
    pub installed: Installed,
    /// What the scan found for its address.
    pub status: ListedAs,
}

/// Compares the gateway's list with what a scan did with each profile module, given as VAG
/// address and outcome. Gives one entry per listed slot in slot order, so an address listed
/// twice shows twice. An address the profile gives more than once (a module tried on ISO-TP, then
/// TP2.0) is [`ListedAs::Found`] if any try answered, then [`ListedAs::Silent`] if any was tried.
#[must_use]
pub fn compare(installed: &[Installed], profile: &[(u8, Tried)]) -> Vec<Compared> {
    installed
        .iter()
        .map(|&installed| {
            let tries = || {
                profile
                    .iter()
                    .filter(move |&&(address, _)| address == installed.address)
                    .map(|&(_, tried)| tried)
            };
            let status = if tries().any(|t| t == Tried::Answered) {
                ListedAs::Found
            } else if tries().any(|t| t == Tried::Silent) {
                ListedAs::Silent
            } else if tries().any(|t| t == Tried::NotTried) {
                ListedAs::NotTried
            } else {
                ListedAs::NotInProfile
            };
            Compared { installed, status }
        })
        .collect()
}
