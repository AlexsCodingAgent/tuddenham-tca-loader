//! BER-TLV, the encoding every GlobalPlatform response is made of.
//!
//! Only what the card management commands need: a flat walk of a byte string into
//! tag/value pairs, nested expansion for constructed tags, and the inverse for building
//! commands. No indefinite lengths, because no card management response uses them.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlvError {
    #[error("truncated tag at offset {0}")]
    TruncatedTag(usize),
    #[error("truncated length at offset {0}")]
    TruncatedLength(usize),
    #[error("value overruns the buffer at offset {0}")]
    TruncatedValue(usize),
    #[error("trailing byte at offset {0}")]
    TrailingByte(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Bit 6 of the first tag byte marks a constructed tag, whose value holds more TLVs.
    pub fn is_constructed(&self) -> bool {
        (self.tag >> 8) as u8 & 0x20 != 0
    }

    pub fn children(&self) -> Result<Vec<Tlv<'a>>, TlvError> {
        parse(self.value)
    }
}

/// Parse a buffer into a flat list of TLVs, stopping on a trailing partial element.
pub fn parse(mut data: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    let input = data;
    let mut out = Vec::new();
    let mut offset = 0usize;

    while !data.is_empty() {
        let start = offset;
        let first = data[0];
        let (tag, tag_len) = if first & 0x1F == 0x1F {
            // Multi-byte tag: continue while the high bit is set, up to 3 extra bytes.
            let mut len = 1usize;
            while len < data.len() && data[len] & 0x80 != 0 {
                len += 1;
            }
            if len >= data.len() {
                return Err(TlvError::TruncatedTag(start));
            }
            len += 1;
            let mut value = 0u32;
            for b in &data[..len] {
                value = (value << 8) | *b as u32;
            }
            (value, len)
        } else {
            (first as u32, 1usize)
        };

        if data.len() < tag_len + 1 {
            return Err(TlvError::TruncatedLength(start));
        }
        let mut idx = tag_len;
        let len_byte = data[idx];
        idx += 1;
        let value_len = if len_byte & 0x80 == 0 {
            len_byte as usize
        } else {
            let n = (len_byte & 0x7F) as usize;
            if n == 0 || n > 3 || data.len() < idx + n {
                return Err(TlvError::TruncatedLength(start));
            }
            let mut v = 0usize;
            for b in &data[idx..idx + n] {
                v = (v << 8) | *b as usize;
            }
            idx += n;
            v
        };

        if data.len() < idx + value_len {
            return Err(TlvError::TruncatedValue(start));
        }
        out.push(Tlv { tag, value: &data[idx..idx + value_len] });
        data = &data[idx + value_len..];
        offset = input.len() - data.len();
    }
    Ok(out)
}

/// Encode one TLV. Tags above 0xFF are written as the two-byte form the card expects.
pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    if tag > 0xFF {
        out.push((tag >> 8) as u8);
        out.push(tag as u8);
    } else {
        out.push(tag as u8);
    }
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.extend_from_slice(&[0x81, value.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// Look up the first value with a given tag, which is how every GP query is read.
pub fn find<'a>(tlvs: &'a [Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_byte_tag_and_short_length() {
        // 9F70 01 07  -> tag 0x9F70, value 07
        let tlvs = parse(&[0x9F, 0x70, 0x01, 0x07]).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x9F70);
        assert_eq!(tlvs[0].value, &[0x07]);
    }

    #[test]
    fn parses_long_form_length() {
        let mut data = vec![0x4F, 0x81, 0x10];
        data.extend_from_slice(&[0xAA; 16]);
        let tlvs = parse(&data).unwrap();
        assert_eq!(tlvs[0].tag, 0x4F);
        assert_eq!(tlvs[0].value.len(), 16);
    }

    #[test]
    fn rejects_a_truncated_value() {
        assert!(matches!(parse(&[0x4F, 0x05, 0x01]), Err(TlvError::TruncatedValue(..))));
    }

    #[test]
    fn encodes_and_round_trips() {
        let encoded = encode(0x9F70, &[0x07]);
        assert_eq!(encoded, vec![0x9F, 0x70, 0x01, 0x07]);
        assert_eq!(parse(&encoded).unwrap()[0].tag, 0x9F70);
    }

    #[test]
    fn find_reads_a_nested_entry() {
        // constructed tag E3 holding 4F 07 A000000003000000 and 9F70 01 07
        let mut inner = vec![0x4F, 0x07];
        inner.extend_from_slice(&[0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00]);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, 0x07]);
        let outer = encode(0xE3, &inner);
        let tlvs = parse(&outer).unwrap();
        let kids = tlvs[0].children().unwrap();
        assert_eq!(find(&kids, 0x4F).unwrap().len(), 7);
        assert_eq!(find(&kids, 0x9F70).unwrap(), &[0x07]);
    }
}
