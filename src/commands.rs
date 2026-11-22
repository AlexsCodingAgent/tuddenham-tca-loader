//! The command payloads behind loading: INSTALL [for load], LOAD, INSTALL [for install], DELETE.
//!
//! These are pure functions that build the data field only, so the encodings can be tested against
//! known byte strings instead of against a card. The shapes are the ones a reference implementation
//! (kaoh/globalplatform) produces:
//!
//! INSTALL [for load]   : load file AID, security domain AID, optional hash, load parameters, token
//! INSTALL [for install]: load file AID, module AID, application AID, privileges, C9 parameters
//! DELETE               : 4F tag with each AID

use crate::tlv;

/// A one-byte length prefix, which is how the AID fields are encoded.
fn lp(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out
}

/// A DER-style length prefix, used where the field can exceed 255 bytes.
fn length_prefix(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// INSTALL [for load]: P1 = 0x02.
///
/// `hash` is the Load File Data Block Hash. Omitting it is normal and means the card does not check
/// the load file's integrity beyond its own parsing.
pub fn install_for_load(load_file_aid: &[u8], sd_aid: &[u8], hash: Option<&[u8]>) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&lp(load_file_aid));
    data.extend_from_slice(&lp(sd_aid));
    match hash {
        Some(h) => data.extend_from_slice(&lp(h)),
        None => data.push(0x00),
    }
    data.push(0x00); // no load parameter block: the card decides its own memory use
    data.push(0x00); // no load token: this is issuer management, not delegated management
    data
}

/// INSTALL [for install] (P1 = 0x04) or [for install and make selectable] (P1 = 0x0C).
pub fn install_for_install(
    load_file_aid: &[u8],
    module_aid: &[u8],
    app_aid: &[u8],
    privileges: u32,
    params: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&lp(load_file_aid));
    data.extend_from_slice(&lp(module_aid));
    data.extend_from_slice(&lp(app_aid));

    // privileges are a 1 to 3 byte big-endian bit string, trimmed but never empty
    let priv_bytes = {
        let raw = privileges.to_be_bytes();
        let first = raw.iter().position(|b| *b != 0).unwrap_or(3);
        raw[first..].to_vec()
    };
    data.push(priv_bytes.len() as u8);
    data.extend_from_slice(&priv_bytes);

    // C9 application parameters, wrapped in a length-prefixed field
    let c9 = tlv::encode(0xC9, params);
    data.extend_from_slice(&length_prefix(c9.len()));
    data.extend_from_slice(&c9);
    data
}

/// DELETE: P1 = 0x00, P2 = 0x00 for the object alone, 0x80 for the object and everything that
/// depends on it.
pub fn delete(aids: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for aid in aids {
        data.extend_from_slice(&tlv::encode(0x4F, aid));
    }
    data
}

pub fn privilege_names(privileges: u32) -> Vec<&'static str> {
    const NAMES: [(u32, &str); 8] = [
        (0x8000_0000 >> 8, "security domain"),
        (0x0000_0040, "card lock"),
        (0x0000_0020, "card terminate"),
        (0x0000_0010, "card reset"),
        (0x0000_0008, "cvm management"),
        (0x0000_0004, "mandated dap"),
        (0x0000_0002, "trusted path"),
        (0x0000_0001, "global registry"),
    ];
    NAMES.iter().filter(|(bit, _)| privileges & bit != 0).map(|(_, n)| *n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKG: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
    const APP: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01, 0x01];
    const ISD: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];

    /// The reference implementation encodes exactly these bytes for the simplest case.
    #[test]
    fn install_for_load_layout() {
        let data = install_for_load(&PKG, &ISD, None);
        assert_eq!(
            hex::encode(&data),
            "07a0000000620101\
             08a000000003000000\
             00\
             00\
             00"
        );
    }

    #[test]
    fn install_for_load_with_a_hash() {
        let hash = [0x11u8; 20];
        let data = install_for_load(&PKG, &ISD, Some(&hash));
        assert!(hex::encode(&data).contains("141111111111111111111111111111111111111111"));
    }

    #[test]
    fn install_for_install_without_privileges() {
        let data = install_for_install(&PKG, &APP, &APP, 0, &[]);
        assert_eq!(
            hex::encode(&data),
            "07a0000000620101\
             08a000000062010101\
             08a000000062010101\
             0100\
             02c900"
        );
    }

    #[test]
    fn privileges_are_trimmed_big_endian() {
        let one = hex::encode(install_for_install(&PKG, &APP, &APP, 0x01, &[]));
        assert!(one.ends_with("01010102c900"), "{one}");
        let two = hex::encode(install_for_install(&PKG, &APP, &APP, 0x8000, &[]));
        assert!(two.ends_with("02800002c900"), "{two}");
        let three = hex::encode(install_for_install(&PKG, &APP, &APP, 0x800001, &[]));
        assert!(three.ends_with("0380000102c900"), "{three}");
    }

    #[test]
    fn install_parameters_ride_inside_c9() {
        let params = [0xDE, 0xAD, 0xBE, 0xEF];
        let data = install_for_install(&PKG, &APP, &APP, 0, &params);
        assert!(hex::encode(&data).ends_with("06c904deadbeef"), "{}", hex::encode(&data));
    }

    #[test]
    fn delete_tags_each_aid() {
        let data = delete(&[&APP, &PKG]);
        assert_eq!(
            hex::encode(&data),
            "4f08a0000000620101014f07a0000000620101"
        );
    }

    #[test]
    fn long_fields_get_a_der_length() {
        assert_eq!(length_prefix(0x7f), vec![0x7f]);
        assert_eq!(length_prefix(0x80), vec![0x81, 0x80]);
        assert_eq!(length_prefix(0x1234), vec![0x82, 0x12, 0x34]);
    }
}
