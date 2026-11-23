//! Finding and opening authenticators.

use crate::authenticator::Authenticator;
use crate::backend;
use crate::error::Error;
use std::ffi::CString;

/// A connected FIDO authenticator, not yet opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    path: CString,
    vendor_id: u16,
    product_id: u16,
    manufacturer: String,
    product: String,
}

impl Device {
    /// The USB vendor id.
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// The USB product id.
    pub fn product_id(&self) -> u16 {
        self.product_id
    }

    /// The manufacturer string, empty if the device gave none.
    pub fn manufacturer(&self) -> &str {
        &self.manufacturer
    }

    /// The product string, empty if the device gave none.
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Where the operating system has the device (on Linux, a
    /// `/dev/hidraw*` node). For display.
    pub fn path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Open the device and allocate a channel on it.
    ///
    /// On Linux a device this user may not open is
    /// [`Error::PermissionDenied`]; the fix is a udev rule, never running
    /// with privileges.
    pub fn open(&self) -> Result<Authenticator, Error> {
        Ok(Authenticator::new(backend::open(&self.path)?))
    }
}

/// The FIDO authenticators connected now (HID usage page `0xF1D0`),
/// ordered by path. An empty list is not an error.
pub fn devices() -> Result<Vec<Device>, Error> {
    Ok(backend::enumerate()?
        .into_iter()
        .map(|f| Device {
            path: f.path,
            vendor_id: f.vendor_id,
            product_id: f.product_id,
            manufacturer: f.manufacturer,
            product: f.product,
        })
        .collect())
}

/// Open the one connected authenticator: [`Error::NoDevice`] if there is
/// none, [`Error::MultipleDevices`] if the caller has to choose (with
/// [`devices`]).
pub fn open_only() -> Result<Authenticator, Error> {
    only(&devices()?)?.open()
}

fn only(found: &[Device]) -> Result<&Device, Error> {
    match found {
        [] => Err(Error::NoDevice),
        [one] => Ok(one),
        many => Err(Error::MultipleDevices(many.len())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(path: &str) -> Device {
        Device {
            path: CString::new(path).unwrap(),
            vendor_id: 0x1050,
            product_id: 0x0402,
            manufacturer: "Maker".into(),
            product: "Key".into(),
        }
    }

    #[test]
    fn exactly_one_device_is_chosen_without_asking() {
        assert!(matches!(only(&[]), Err(Error::NoDevice)));
        let one = [device("/dev/hidraw0")];
        assert_eq!(only(&one).unwrap().path(), "/dev/hidraw0");
        let two = [device("/dev/hidraw0"), device("/dev/hidraw1")];
        assert!(matches!(only(&two), Err(Error::MultipleDevices(2))));
    }

    #[test]
    fn a_device_describes_itself() {
        let d = device("/dev/hidraw0");
        assert_eq!((d.vendor_id(), d.product_id()), (0x1050, 0x0402));
        assert_eq!((d.manufacturer(), d.product()), ("Maker", "Key"));
    }
}
