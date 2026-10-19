//! Minimal binary encoding: `magic(4) ‖ version(1) ‖ fields`, where variable
//! fields are `u32 big-endian length ‖ bytes`.

use crate::error::{Error, Result};

/// Wire format version.
pub const VERSION: u8 = 1;

/// Encoder for one message.
pub struct Writer(Vec<u8>);

impl Writer {
    /// Start a message with its 4-byte magic and the format version.
    #[must_use]
    pub fn new(magic: [u8; 4]) -> Self {
        let mut buf = Vec::with_capacity(4096);
        buf.extend_from_slice(&magic);
        buf.push(VERSION);
        Self(buf)
    }

    /// One byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// A big-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Fixed-length bytes, without a length prefix.
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// Length-prefixed bytes.
    ///
    /// # Panics
    ///
    /// For a field of 4 GiB or more.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        let len = u32::try_from(bytes.len()).expect("field shorter than 4 GiB");
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    /// A length-prefixed UTF-8 string.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// The encoded message.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Decoder for one message.  Every read fails with [`Error::Malformed`]
/// naming the message when the input is too short.
pub struct Reader<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    /// Check the magic and version.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for another magic or version.
    pub fn new(buf: &'a [u8], magic: [u8; 4], what: &'static str) -> Result<Self> {
        let mut r = Self { buf, what };
        if r.fixed::<4>()? != magic || r.u8()? != VERSION {
            return Err(Error::Malformed(what));
        }
        Ok(r)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(self.malformed());
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// The error for this message.
    #[must_use]
    pub fn malformed(&self) -> Error {
        Error::Malformed(self.what)
    }

    /// One byte.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// A big-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    /// `N` fixed bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Length-prefixed bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.fixed()?);
        self.take(usize::try_from(len).map_err(|_| self.malformed())?)
    }

    /// Like [`bytes`](Self::bytes), but the length must be exactly `len`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn bytes_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let b = self.bytes()?;
        if b.len() == len {
            Ok(b)
        } else {
            Err(self.malformed())
        }
    }

    /// A length-prefixed UTF-8 string.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for invalid UTF-8.
    pub fn str(&mut self) -> Result<&'a str> {
        let b = self.bytes()?;
        std::str::from_utf8(b).map_err(|_| self.malformed())
    }

    /// Require that nothing is left.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for trailing bytes.
    pub fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(self.malformed())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects_garbage() {
        let enc = Writer::new(*b"TEST")
            .u8(7)
            .fixed(&[1, 2])
            .bytes(b"abc")
            .u64(0x0102_0304_0506_0708)
            .str("é")
            .finish();
        let mut r = Reader::new(&enc, *b"TEST", "test").unwrap();
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.fixed::<2>().unwrap(), [1, 2]);
        assert_eq!(r.bytes().unwrap(), b"abc");
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.str().unwrap(), "é");
        r.finish().unwrap();

        assert!(Reader::new(&enc, *b"NOPE", "test").is_err());
        let truncated = Writer::new(*b"TEST").bytes(b"abc").finish();
        let mut r = Reader::new(&truncated[..truncated.len() - 1], *b"TEST", "test").unwrap();
        assert!(r.bytes().is_err());
    }
}
