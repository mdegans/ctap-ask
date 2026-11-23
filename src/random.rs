//! Randomness from the operating system.

use crate::error::Error;

/// Fill `buf` with random bytes from the operating system.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(randomness)
}

pub(crate) fn randomness(e: getrandom::Error) -> Error {
    Error::Randomness(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_something() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        let e = randomness(getrandom::Error::UNSUPPORTED);
        assert!(matches!(e, Error::Randomness(_)));
        assert!(
            e.to_string()
                .starts_with("the operating system gave no randomness")
        );
    }
}
