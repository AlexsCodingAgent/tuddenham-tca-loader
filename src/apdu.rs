//! APDU framing and status words.
//!
//! The loader speaks ISO 7816-4 command APDUs over whatever transport carries them, so the
//! framing lives here and nothing above this module knows about PC/SC or SMS.

use thiserror::Error;

/// GlobalPlatform wants 255-byte blocks for LOAD, and most cards answer a plain Le=0.
pub const MAX_BLOCK: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl Command {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self { cla, ins, p1, p2, data: Vec::new(), le: None }
    }

    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        self
    }

    pub fn le(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    /// Short-form encoding: 5 bytes when there is no data, and a trailing Le byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 6);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApduError {
    #[error("response is shorter than two status bytes")]
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Response {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApduError> {
        if bytes.len() < 2 {
            return Err(ApduError::Truncated);
        }
        let split = bytes.len() - 2;
        Ok(Self { data: bytes[..split].to_vec(), sw1: bytes[split], sw2: bytes[split + 1] })
    }

    pub fn status(&self) -> u16 {
        u16::from_be_bytes([self.sw1, self.sw2])
    }

    pub fn is_ok(&self) -> bool {
        self.status() == 0x9000
    }

    /// The card asking for more time is not a failure, and 61xx names how many bytes are
    /// waiting, which the caller fetches with GET RESPONSE.
    pub fn more_time(&self) -> bool {
        self.sw1 == 0x6C
    }

    pub fn available(&self) -> Option<u8> {
        (self.sw1 == 0x61).then_some(self.sw2)
    }

    pub fn describe(&self) -> &'static str {
        match self.status() {
            0x9000 => "success",
            0x6982 => "security status not satisfied: authenticate before this command",
            0x6985 => "conditions of use not satisfied: state or policy forbids it",
            0x6986 => "command not allowed: no current application selected",
            0x6A80 => "wrong data: malformed or unsupported value",
            0x6A84 => "not enough memory on the card",
            0x6A88 => "referenced data not found",
            0x6881 => "logical channel not supported: this card has channel 0 only",
            0x6882 => "secure messaging not supported here: the card refuses INITIALIZE UPDATE in \
                       its current state or for this key version",
            0x6883 => "last command of the chain expected",
            0x6884 => "command chaining not supported",
            0x6A82 => "file or application not found",
            0x6A86 => "incorrect P1 or P2",
            0x6D00 => "instruction not supported by this card",
            0x6E00 => "class not supported by this card",
            _ => "unrecognised status word",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_select_by_aid() {
        let cmd = Command::new(0x00, 0xA4, 0x04, 0x00)
            .data(vec![0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00])
            .le(0x00);
        assert_eq!(cmd.encode().len(), 13);
        assert_eq!(&cmd.encode()[3..5], &[0x00, 0x07]);
    }

    #[test]
    fn splits_status_word_off_the_response() {
        let r = Response::from_bytes(&[0x66, 0x01, 0x90, 0x00]).unwrap();
        assert_eq!(r.data, vec![0x66, 0x01]);
        assert!(r.is_ok());
    }

    #[test]
    fn short_response_is_an_error_not_an_empty_success() {
        assert_eq!(Response::from_bytes(&[0x90]), Err(ApduError::Truncated));
    }

    #[test]
    fn explains_a_security_failure() {
        let r = Response::from_bytes(&[0x69, 0x82]).unwrap();
        assert!(!r.is_ok());
        assert!(r.describe().contains("authenticate"));
    }
}
