//! Pure codecs for CAN, ISO-TP, OBD-II and UDS. No IO, `no_std`.
#![no_std]

pub mod isotp;
pub mod obd;
pub mod response;
