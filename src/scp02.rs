//! SCP02, the 3DES secure channel that predates SCP03 and still runs on most SIMs in the field.
//!
//! The shape differs from SCP03 in three ways that matter: keys are 3DES rather than AES, the card
//! sends a sequence counter with its challenge, and the session keys are derived by encrypting a
//! sixteen byte constant rather than by a CMAC-based KDF. The cryptograms use S-ENC as a CBC-MAC
//! key, not S-MAC, which is the detail most implementations get wrong first.

use aes::cipher::KeyInit;
use des::cipher::generic_array::GenericArray;
use des::cipher::BlockEncrypt;
use des::{TdesEde2, TdesEde3};

pub const DERIV_S_ENC: [u8; 2] = [0x01, 0x82];
pub const DERIV_S_MAC: [u8; 2] = [0x01, 0x01];
pub const DERIV_S_RMAC: [u8; 2] = [0x01, 0x02];
pub const DERIV_DEK: [u8; 2] = [0x01, 0x81];

#[derive(Clone, Debug)]
pub struct Scp02Keys {
    /// 16 bytes for 2-key 3DES, 24 for 3-key.
    pub enc: Vec<u8>,
    pub mac: Vec<u8>,
    pub dek: Vec<u8>,
}

/// One block of 3DES-EDE, keyed by 16 or 24 bytes.
fn encrypt_block(key: &[u8], block: &[u8; 8]) -> [u8; 8] {
    let mut out = GenericArray::clone_from_slice(block);
    match key.len() {
        16 => {
            let cipher = TdesEde2::new_from_slice(key).expect("16-byte key");
            cipher.encrypt_block(&mut out);
        }
        24 => {
            let cipher = TdesEde3::new_from_slice(key).expect("24-byte key");
            cipher.encrypt_block(&mut out);
        }
        other => panic!("3DES key must be 16 or 24 bytes, got {other}"),
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&out);
    bytes
}

/// CBC encryption, no padding added: callers decide how to pad.
fn cbc_encrypt(key: &[u8], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let mut chain = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..8 {
            block[i] ^= chain[i];
        }
        chain = encrypt_block(key, &block);
        out.extend_from_slice(&chain);
    }
    out
}

/// CBC-MAC: pad with 0x80 then zeros to a block boundary, encrypt from the given ICV, take the last
/// block. This is the card cryptogram, the host cryptogram and the C-MAC, all with different keys.
pub fn mac(key: &[u8], icv: &[u8; 8], data: &[u8]) -> [u8; 8] {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 8 != 0 {
        padded.push(0x00);
    }
    let encrypted = cbc_encrypt(key, icv, &padded);
    let mut out = [0u8; 8];
    out.copy_from_slice(&encrypted[encrypted.len() - 8..]);
    out
}

/// Session key derivation: constant (2) || sequence counter (2) || twelve zeros, encrypted with the
/// static key in CBC mode under a zero IV.
pub fn derive_session_key(static_key: &[u8], constant: [u8; 2], sequence_counter: &[u8]) -> Vec<u8> {
    let mut data = vec![constant[0], constant[1]];
    data.extend_from_slice(sequence_counter);
    data.resize(16, 0x00);
    cbc_encrypt(static_key, &[0u8; 8], &data)
}

#[derive(Debug, Clone)]
pub struct Scp02Session {
    pub s_enc: Vec<u8>,
    pub s_mac: Vec<u8>,
    pub s_rmac: Vec<u8>,
    pub icv: [u8; 8],
    pub sequence_counter: Vec<u8>,
}

impl Scp02Session {
    pub fn derive(keys: &Scp02Keys, sequence_counter: &[u8]) -> Self {
        Self {
            s_enc: derive_session_key(&keys.enc, DERIV_S_ENC, sequence_counter),
            s_mac: derive_session_key(&keys.mac, DERIV_S_MAC, sequence_counter),
            s_rmac: derive_session_key(&keys.mac, DERIV_S_RMAC, sequence_counter),
            icv: [0u8; 8],
            sequence_counter: sequence_counter.to_vec(),
        }
    }

    /// Card cryptogram: S-ENC over host challenge || sequence counter || card challenge.
    pub fn card_cryptogram(keys: &Scp02Keys, host_challenge: &[u8], sequence_counter: &[u8],
                           card_challenge: &[u8]) -> [u8; 8] {
        let s_enc = derive_session_key(&keys.enc, DERIV_S_ENC, sequence_counter);
        let mut message = Vec::new();
        message.extend_from_slice(host_challenge);
        message.extend_from_slice(sequence_counter);
        message.extend_from_slice(card_challenge);
        mac(&s_enc, &[0u8; 8], &message)
    }

    /// Host cryptogram: the same key over sequence counter || card challenge || host challenge.
    pub fn host_cryptogram(keys: &Scp02Keys, host_challenge: &[u8], sequence_counter: &[u8],
                           card_challenge: &[u8]) -> [u8; 8] {
        let s_enc = derive_session_key(&keys.enc, DERIV_S_ENC, sequence_counter);
        let mut message = Vec::new();
        message.extend_from_slice(sequence_counter);
        message.extend_from_slice(card_challenge);
        message.extend_from_slice(host_challenge);
        mac(&s_enc, &[0u8; 8], &message)
    }

    /// C-MAC over the ICV and the APDU whose Lc already includes the MAC. The ICV becomes the MAC.
    pub fn c_mac(&mut self, apdu: &[u8]) -> [u8; 8] {
        let mut input = self.icv.to_vec();
        input.extend_from_slice(apdu);
        let mac = mac(&self.s_mac, &[0u8; 8], &input);
        self.icv = mac;
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexc(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn cbc_mac_pads_with_80_then_zeros() {
        let key = hexc("0123456789abcdef0123456789abcdef");
        // empty input pads to a single 0x80 block
        assert_eq!(mac(&key, &[0u8; 8], &[]), encrypt_block(&key, &[0x80, 0, 0, 0, 0, 0, 0, 0]));
        // an exact multiple of the block size still gets a whole padding block
        let first = encrypt_block(&key, &[0u8; 8]);
        let mut second_input = first;
        second_input[0] ^= 0x80;
        assert_eq!(mac(&key, &[0u8; 8], &[0u8; 8]), encrypt_block(&key, &second_input));
    }

    #[test]
    fn derivation_is_sixteen_bytes_and_depends_on_the_counter() {
        let key = hexc("404142434445464748494a4b4c4d4e4f");
        let a = derive_session_key(&key, DERIV_S_ENC, &[0x00, 0x01]);
        let b = derive_session_key(&key, DERIV_S_ENC, &[0x00, 0x02]);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        // different constants must give different keys
        assert_ne!(a, derive_session_key(&key, DERIV_S_MAC, &[0x00, 0x01]));
    }

    /// Cross-check: these values come from an independent implementation (pycryptodome DES3, CBC
    /// with a zero IV) following GlobalPlatform's SCP02 rules. If they fail, the derivation or the
    /// MAC in here disagrees with everyone else's card.
    #[test]
    fn matches_an_independent_implementation() {
        let keys = Scp02Keys {
            enc: hexc("404142434445464748494a4b4c4d4e4f"),
            mac: hexc("505152535455565758595a5b5c5d5e5f"),
            dek: hexc("606162636465666768696a6b6c6d6e6f"),
        };
        let seq = hexc("0001");
        assert_eq!(hex::encode(derive_session_key(&keys.enc, DERIV_S_ENC, &seq)),
                   "25c9794a1205ff244f5fa0378d2f8d59");
        assert_eq!(hex::encode(derive_session_key(&keys.mac, DERIV_S_MAC, &seq)),
                   "a6c78e807ad1f4d83603233e01f87bea");
        let host = hexc("0001020304050607");
        let card = hexc("08090A0B0C0D");
        assert_eq!(hex::encode(Scp02Session::card_cryptogram(&keys, &host, &seq, &card)),
                   "9d8da672f05c4e45");
        assert_eq!(hex::encode(Scp02Session::host_cryptogram(&keys, &host, &seq, &card)),
                   "e87e4c9e45c47f79");
    }
}
