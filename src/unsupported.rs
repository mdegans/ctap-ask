//! The backend on a platform that has none yet (Windows): every call says
//! so. See the README for why raw HID is not the path there.

use crate::error::Error;
use crate::transport::CborTransport;
use std::ffi::{CStr, CString};

const WHY: &str = "this platform has no backend yet (Windows needs the system WebAuthn API)";

pub(crate) struct Found {
    pub(crate) path: CString,
    pub(crate) vendor_id: u16,
    pub(crate) product_id: u16,
    pub(crate) manufacturer: String,
    pub(crate) product: String,
}

pub(crate) fn enumerate() -> Result<Vec<Found>, Error> {
    Err(Error::Unsupported(WHY))
}

pub(crate) fn open(_path: &CStr) -> Result<Box<dyn CborTransport>, Error> {
    Err(Error::Unsupported(WHY))
}
