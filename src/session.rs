//! The authenticated session: INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, then wrapped commands.
//!
//! Kept apart from `scp03` so the crypto stays testable without a card, and apart from `gp` so
//! the read path still works on cards that refuse a channel.

use anyhow::{bail, Context as _, Result};

use crate::apdu::{Command, Response};
use crate::card::Transport;
use crate::scp03::{Scp03Keys, SessionKeys};

/// A live secure channel. Holds the session keys and the MAC chaining value, which advances with
/// every command and is why the same command sent twice never carries the same MAC.
pub struct Session {
    pub keys: SessionKeys,
    pub mode: usize,
}

impl Session {
    /// Ask the card for a challenge and prove we hold the static keys.
    pub fn establish<T: Transport>(card: &mut T, keys: &Scp03Keys, security_level: u8) -> Result<Self> {
        let host_challenge = random_challenge();
        let cmd = Command::new(0x80, 0x50, 0x00, 0x00)
            .data(host_challenge.to_vec())
            .le(0x00)
            .encode();
        let resp = card.transmit(&cmd).context("INITIALIZE UPDATE")?;
        let response = Response::from_bytes(&resp)?;
        if !response.is_ok() {
            bail!("card refused INITIALIZE UPDATE: {} ({:04X})",
                  response.describe(), response.status());
        }
        let body = &response.data;
        if body.len() < 29 {
            bail!("INITIALIZE UPDATE returned {} bytes, too short for SCP03", body.len());
        }
        // key diversification data (10), key version (1), SCP identifier (1), i (1), then the
        // card challenge and card cryptogram, each the length of the secure-channel mode
        if body[11] != 0x03 {
            bail!("card speaks SCP{:02X}, this loader speaks SCP03", body[11]);
        }
        let rest = body.len() - 13;
        if rest % 2 != 0 || !(16..=64).contains(&rest) {
            bail!("unexpected SCP03 challenge length {rest}");
        }
        let mode = rest / 2;
        let card_challenge = &body[13..13 + mode];
        let card_cryptogram = &body[13 + mode..13 + 2 * mode];

        let expected = SessionKeys::card_cryptogram(keys, &host_challenge, card_challenge, mode);
        if !constant_time_eq(&expected, card_cryptogram) {
            bail!("card cryptogram did not verify: the static keys are not the card's");
        }

        let session_keys = SessionKeys::derive(keys, &host_challenge, card_challenge, mode);
        let host_cryptogram = SessionKeys::host_cryptogram(keys, &host_challenge, card_challenge, mode);

        let mut session = Self { keys: session_keys, mode };
        // EXTERNAL AUTHENTICATE carries the host cryptogram and a C-MAC over itself
        let mut data = host_cryptogram;
        let header = [0x84u8, 0x82, security_level, 0x00, (data.len() + mode) as u8];
        let mut apdu = header.to_vec();
        apdu.extend_from_slice(&data);
        let mac = session.keys.c_mac(&apdu);
        data.extend_from_slice(&mac[..mode]);
        let cmd = Command::new(0x84, 0x82, security_level, 0x00).data(data).le(0x00).encode();
        let resp = card.transmit(&cmd).context("EXTERNAL AUTHENTICATE")?;
        let response = Response::from_bytes(&resp)?;
        if !response.is_ok() {
            bail!("card rejected EXTERNAL AUTHENTICATE: {} ({:04X})",
                  response.describe(), response.status());
        }
        Ok(session)
    }

    /// Wrap a command with a C-MAC. Response protection is not applied here: the loader asks for
    /// security level 0x01, which is C-MAC only, so the card answers in the clear.
    pub fn wrap(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
        let mcla = (cla & 0xF0) | 0x04;
        let lc = data.len() + self.mode;
        let mut apdu = vec![mcla, ins, p1, p2, lc as u8];
        apdu.extend_from_slice(data);
        let mac = self.keys.c_mac(&apdu);
        apdu.extend_from_slice(&mac[..self.mode]);
        if let Some(le) = le {
            apdu.push(le);
        }
        apdu
    }

    pub fn transmit<T: Transport>(&mut self, card: &mut T, apdu: &[u8]) -> Result<Response> {
        let raw = card.transmit(apdu)?;
        Ok(Response::from_bytes(&raw)?)
    }
}

fn random_challenge() -> [u8; 8] {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // Never reuse a fixed challenge in anger, but a clock-derived one is still better than zero
    // when /dev/urandom is unavailable, and the card cryptogram check is what actually matters.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    buf.copy_from_slice(&nanos.to_be_bytes()[8..]);
    buf
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("mode", &self.mode)
            .field("s_enc", &"<derived>")
            .field("s_mac", &"<derived>")
            .finish()
    }
}
