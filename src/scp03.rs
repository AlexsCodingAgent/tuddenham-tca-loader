//! SCP03, the secure channel every modern GlobalPlatform card expects.
//!
//! Nothing can be loaded onto a card until a session exists, so this is the gate: the host sends
//! a challenge, the card answers with its own challenge and a cryptogram, both sides derive
//! session keys from the static keys plus both challenges, and the host proves it can compute
//! the same cryptogram. Get any byte of that wrong and the card answers 6A 81 forever.
//!
//! The derivation is NIST SP 800-108 counter mode with CMAC-AES as the PRF, but GlobalPlatform
//! orders the fields its own way (a 12-byte label of eleven zeros and the derivation constant,
//! then a separator, the length, the block counter and the context), which is why the stock
//! SP800-108 helper cannot be reused.

use aes::cipher::KeyInit;
use aes::Aes128;
use cmac::{Cmac, Mac};

pub const DERIV_CARD_CRYPTOGRAM: u8 = 0x00;
pub const DERIV_HOST_CRYPTOGRAM: u8 = 0x01;
pub const DERIV_S_ENC: u8 = 0x04;
pub const DERIV_S_MAC: u8 = 0x06;
pub const DERIV_S_RMAC: u8 = 0x07;

/// GlobalPlatform's static test keys. Present so a card can be exercised without inventing keys,
/// and named so nobody mistakes them for production material.
pub const TEST_KEYS: Scp03Keys = Scp03Keys {
    enc: [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f],
    mac: [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f],
    dek: [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f],
};

#[derive(Clone, Copy, Debug)]
pub struct Scp03Keys {
    pub enc: [u8; 16],
    pub mac: [u8; 16],
    pub dek: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub s_enc: Vec<u8>,
    pub s_mac: Vec<u8>,
    pub s_rmac: Vec<u8>,
    pub mac_chaining: Vec<u8>,
}

pub fn cmac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("AES-128 key length");
    Mac::update(&mut mac, data);
    let out = <Cmac<Aes128> as Mac>::finalize(mac).into_bytes();
    let mut block = [0u8; 16];
    block.copy_from_slice(&out);
    block
}

/// KDF in counter mode, GlobalPlatform's field order. `bits` is the output length in bits.
pub fn kdf(base_key: &[u8], constant: u8, context: &[u8], bits: usize) -> Vec<u8> {
    let bytes = bits / 8;
    let mut label = [0u8; 12];
    label[11] = constant;
    let mut out = Vec::with_capacity(bytes);
    let mut counter: u8 = 1;
    while out.len() < bytes {
        let mut info = Vec::with_capacity(12 + 1 + 2 + 1 + context.len());
        info.extend_from_slice(&label);
        info.push(0x00);
        info.extend_from_slice(&(bits as u16).to_be_bytes());
        info.push(counter);
        info.extend_from_slice(context);
        out.extend_from_slice(&cmac(base_key, &info));
        counter = counter.wrapping_add(1);
    }
    out.truncate(bytes);
    out
}

impl SessionKeys {
    /// Derive the session keys and both cryptograms from the two challenges.
    pub fn derive(static_keys: &Scp03Keys, host_challenge: &[u8], card_challenge: &[u8], _mode: usize) -> Self {
        let mut context = Vec::new();
        context.extend_from_slice(host_challenge);
        context.extend_from_slice(card_challenge);
        let s_enc = kdf(&static_keys.enc, DERIV_S_ENC, &context, 128);
        let s_mac = kdf(&static_keys.mac, DERIV_S_MAC, &context, 128);
        let s_rmac = kdf(&static_keys.mac, DERIV_S_RMAC, &context, 128);
        Self { s_enc, s_mac, s_rmac, mac_chaining: vec![0u8; 16] }
    }

    pub fn card_cryptogram(static_keys: &Scp03Keys, host_challenge: &[u8], card_challenge: &[u8], mode: usize) -> Vec<u8> {
        let mut context = Vec::new();
        context.extend_from_slice(host_challenge);
        context.extend_from_slice(card_challenge);
        kdf(&static_keys.mac, DERIV_CARD_CRYPTOGRAM, &context, mode * 8)
    }

    pub fn host_cryptogram(static_keys: &Scp03Keys, host_challenge: &[u8], card_challenge: &[u8], mode: usize) -> Vec<u8> {
        let mut context = Vec::new();
        context.extend_from_slice(host_challenge);
        context.extend_from_slice(card_challenge);
        kdf(&static_keys.mac, DERIV_HOST_CRYPTOGRAM, &context, mode * 8)
    }

    /// C-MAC over a command: chaining value then the APDU whose Lc already includes the MAC.
    /// The return value is the full 16-byte CMAC; callers truncate to the mode.
    pub fn c_mac(&mut self, apdu: &[u8]) -> [u8; 16] {
        let mut input = Vec::with_capacity(self.mac_chaining.len() + apdu.len());
        input.extend_from_slice(&self.mac_chaining);
        input.extend_from_slice(apdu);
        let mac = cmac(&self.s_mac, &input);
        self.mac_chaining = mac.to_vec();
        mac
    }

    pub fn r_mac(&self, response_data: &[u8]) -> [u8; 16] {
        let mut input = Vec::with_capacity(self.mac_chaining.len() + response_data.len());
        input.extend_from_slice(&self.mac_chaining);
        input.extend_from_slice(response_data);
        cmac(&self.s_rmac, &input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexc(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// RFC 4493, so the CMAC in here is the CMAC everyone else means.
    #[test]
    fn cmac_matches_rfc4493() {
        let key = hexc("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(hex::encode(cmac(&key, b"")), "bb1d6929e95937287fa37d129b756746");
        assert_eq!(
            hex::encode(cmac(&key, &hexc("6bc1bee22e409f96e93d7e117393172a"))),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
        let long = hexc("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
        assert_eq!(hex::encode(cmac(&key, &long)), "dfa66747de9ae63030ca32611497c827");
    }

    #[test]
    fn kdf_is_deterministic_and_length_aware() {
        let context = hexc("000102030405060708090a0b0c0d0e0f");
        let a = kdf(&TEST_KEYS.enc, DERIV_S_ENC, &context, 128);
        let b = kdf(&TEST_KEYS.enc, DERIV_S_ENC, &context, 128);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        let short = kdf(&TEST_KEYS.mac, DERIV_CARD_CRYPTOGRAM, &context, 64);
        assert_eq!(short.len(), 8);
        // a different constant must give different key material
        assert_ne!(a, kdf(&TEST_KEYS.enc, DERIV_S_MAC, &context, 128));
    }

    /// Cross-check: these values were produced by an independent implementation (pycryptodome
    /// CMAC with GlobalPlatform's field order) for the standard test keys and challenges. If
    /// this test fails, the KDF in here disagrees with the rest of the world, not with itself.
    #[test]
    fn kdf_matches_an_independent_implementation() {
        let host = hexc("0001020304050607");
        let card = hexc("08090a0b0c0d0e0f");
        let mut ctx = host.clone();
        ctx.extend_from_slice(&card);
        assert_eq!(hex::encode(kdf(&TEST_KEYS.enc, DERIV_S_ENC, &ctx, 128)),
                   "eb845bbc703969a9b312a5f8e4834aa2");
        assert_eq!(hex::encode(kdf(&TEST_KEYS.mac, DERIV_S_MAC, &ctx, 128)),
                   "c6e2cc87fb9c0fe79818e0802fa952cc");
        assert_eq!(hex::encode(kdf(&TEST_KEYS.mac, DERIV_S_RMAC, &ctx, 128)),
                   "3bc6f5baccd1c57193f97cae45dc7350");
        assert_eq!(hex::encode(SessionKeys::card_cryptogram(&TEST_KEYS, &host, &card, 8)),
                   "30559bcf65c936ce");
        assert_eq!(hex::encode(SessionKeys::host_cryptogram(&TEST_KEYS, &host, &card, 8)),
                   "5af063777b451d3b");
    }

    #[test]
    fn cryptograms_differ_and_have_the_mode_length() {
        let host = hexc("0001020304050607");
        let card = hexc("08090a0b0c0d0e0f");
        let c = SessionKeys::card_cryptogram(&TEST_KEYS, &host, &card, 8);
        let h = SessionKeys::host_cryptogram(&TEST_KEYS, &host, &card, 8);
        assert_eq!(c.len(), 8);
        assert_eq!(h.len(), 8);
        assert_ne!(c, h);
    }

    #[test]
    fn c_mac_chains() {
        let host = hexc("0001020304050607");
        let card = hexc("08090a0b0c0d0e0f");
        let mut sk = SessionKeys::derive(&TEST_KEYS, &host, &card, 8);
        let first = sk.c_mac(&[0x84, 0x82, 0x33, 0x00, 0x10]);
        let second = sk.c_mac(&[0x84, 0x82, 0x33, 0x00, 0x10]);
        assert_ne!(first, second, "chaining means the same command twice differs");
        assert_eq!(sk.mac_chaining, second.to_vec());
    }
}
