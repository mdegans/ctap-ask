//! The USB HID backend, over `hidapi`. Linux and macOS.

use crate::error::Error;
use crate::transport::{CborTransport, Ctaphid, PACKET, PacketIo};
use hidapi::{HidApi, HidDevice};
use std::ffi::{CStr, CString};
use std::time::Duration;

/// The FIDO usage page and the CTAPHID usage (CTAP 2.1 §11.2.8.1).
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

pub(crate) struct Found {
    pub(crate) path: CString,
    pub(crate) vendor_id: u16,
    pub(crate) product_id: u16,
    pub(crate) manufacturer: String,
    pub(crate) product: String,
}

fn api() -> Result<HidApi, Error> {
    HidApi::new().map_err(|e| Error::Io(format!("initialising HID: {e}")))
}

pub(crate) fn enumerate() -> Result<Vec<Found>, Error> {
    let api = api()?;
    let mut out: Vec<Found> = api
        .device_list()
        .filter(|d| d.usage_page() == FIDO_USAGE_PAGE && d.usage() == FIDO_USAGE_CTAPHID)
        .map(|d| Found {
            path: d.path().to_owned(),
            vendor_id: d.vendor_id(),
            product_id: d.product_id(),
            manufacturer: d.manufacturer_string().unwrap_or("").to_string(),
            product: d.product_string().unwrap_or("").to_string(),
        })
        .collect();
    // hidapi may list one interface more than once on some platforms.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    Ok(out)
}

pub(crate) fn open(path: &CStr) -> Result<Box<dyn CborTransport>, Error> {
    let dev = api()?
        .open_path(path)
        .map_err(|e| open_error(&path.to_string_lossy(), &e.to_string()))?;
    Ok(Box::new(Ctaphid::open(HidIo(dev))?))
}

/// hidapi reports a failed open as text. A refusal for permissions gets
/// its own error, because what to do about it is different.
pub(crate) fn open_error(path: &str, detail: &str) -> Error {
    if detail.contains("Permission denied") || detail.contains("os error 13") {
        Error::PermissionDenied {
            path: path.to_string(),
        }
    } else {
        Error::Open {
            path: path.to_string(),
            detail: detail.to_string(),
        }
    }
}

struct HidIo(HidDevice);

impl PacketIo for HidIo {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<(), Error> {
        // hidapi wants the report id (0: the device has none) first.
        let mut report = [0u8; PACKET + 1];
        report[1..].copy_from_slice(packet);
        self.0
            .write(&report)
            .map_err(|e| Error::Io(format!("write: {e}")))?;
        Ok(())
    }

    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; PACKET]>, Error> {
        let mut buf = [0u8; PACKET];
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let n = self
            .0
            .read_timeout(&mut buf, ms)
            .map_err(|e| Error::Io(format!("read: {e}")))?;
        Ok((n > 0).then_some(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permission_refusal_is_told_apart() {
        let e = open_error(
            "/dev/hidraw3",
            "hidapi error: failed to open device with path /dev/hidraw3: Permission denied (os error 13)",
        );
        assert!(matches!(e, Error::PermissionDenied { ref path } if path == "/dev/hidraw3"));
        let e = open_error("/dev/hidraw3", "hidapi error: device busy");
        assert!(matches!(e, Error::Open { .. }));
        assert!(e.to_string().contains("device busy"));
    }
}
