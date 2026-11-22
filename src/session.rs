//! The authenticated session: INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, then wrapped commands.
//!
//! Both secure channel protocols a UICC is likely to speak are here. The card announces which one
//! it uses in the INITIALIZE UPDATE response, so the host does not have to guess: byte 11 of the
//! response is the SCP identifier, and the rest is parsed according to it.

use anyhow::{bail, Context as _, Result};

use crate::apdu::{Command, Response};
use crate::card::Transport;
use crate::scp02::{Scp02Keys, Scp02Session};
use crate::scp03::{Scp03Keys, SessionKeys};

/// The static keys a card might use. Which one applies is the card's choice, not the caller's.
#[derive(Clone, Debug)]
pub enum StaticKeys {
    Scp03(Scp03Keys),
    Scp02(Scp02Keys),
}

impl StaticKeys {
    pub fn describe(&self) -> String {
        match self {
            Self::Scp03(_) => "SCP03 (AES)".into(),
            Self::Scp02(k) => format!("SCP02 (3DES, {}-byte keys)", k.enc.len()),
        }
    }
}

enum Channel {
    Scp03(SessionKeys),
    Scp02(Scp02Session),
}

/// A live secure channel. Holds the session keys and the MAC chaining value, which advances with
/// every command and is why the same command sent twice never carries the same MAC.
pub struct Session {
    channel: Channel,
    pub mode: usize,
    pub scp: u8,
    /// The security domain that received the load file. Every INSTALL names it.
    pub sd_aid: Vec<u8>,
}

/// What the card disclosed in INITIALIZE UPDATE, before any key is used.
#[derive(Debug, Clone)]
pub struct CardChallenge {
    pub host_challenge: Vec<u8>,
    pub card_challenge: Vec<u8>,
    pub card_cryptogram: Vec<u8>,
    /// 8 for SCP03 S8, 16 for S16, 6 for SCP02.
    pub mode: usize,
    pub scp: u8,
    /// SCP02 only: the sequence counter the session keys are derived from.
    pub sequence_counter: Vec<u8>,
}

/// The verdict of checking static keys against a card, which costs the card nothing: no
/// EXTERNAL AUTHENTICATE is sent, so a wrong key does not spend an authentication attempt.
#[derive(Debug, Clone)]
pub struct KeyCheck {
    pub matches: bool,
    pub challenge: CardChallenge,
}

impl Session {
    /// Ask the card for a challenge without presenting any key, and parse it in whichever protocol
    /// the card announces.
    pub fn challenge<T: Transport>(card: &mut T) -> Result<CardChallenge> {
        let host_challenge = random_challenge();
        let cmd = Command::new(0x80, 0x50, 0x00, 0x00)
            .data(host_challenge.clone())
            .le(0x00)
            .encode();
        let resp = card.transmit(&cmd).context("INITIALIZE UPDATE")?;
        let response = Response::from_bytes(&resp)?;
        if !response.is_ok() {
            let sw = response.status();
            let extra = match sw {
                0x6882 => "\n  The card manager exists and advertises a secure channel, but will not \
start one now. On SIM-shaped cards this usually means the domain is terminated, locked, or \
waiting for a state change that needs an authentication you do not have. GET DATA 00E0 still \
answers, and lists the key versions and types you would need.",
                0x6E00 => "\n  CLA 0x80 is not supported by the selected application: it is a USIM or \
ISIM applet, not a GlobalPlatform security domain. Select the card manager AID first.",
                _ => "",
            };
            bail!("card refused INITIALIZE UPDATE: {} ({:04X}){extra}",
                  response.describe(), sw);
        }
        let body = &response.data;
        if body.len() < 28 {
            bail!("INITIALIZE UPDATE returned {} bytes, too short for a sane secure channel", body.len());
        }
        // key diversification data (10), key version (1), SCP identifier (1)
        let scp = body[11];
        match scp {
            0x03 => {
                let rest = body.len() - 13;
                if rest % 2 != 0 || !(16..=64).contains(&rest) {
                    bail!("unexpected SCP03 challenge length {rest}");
                }
                let mode = rest / 2;
                Ok(CardChallenge {
                    host_challenge,
                    card_challenge: body[13..13 + mode].to_vec(),
                    card_cryptogram: body[13 + mode..13 + 2 * mode].to_vec(),
                    mode,
                    scp,
                    sequence_counter: Vec::new(),
                })
            }
            0x02 => Ok(CardChallenge {
                host_challenge,
                card_challenge: body[14..20].to_vec(),
                card_cryptogram: body[20..28].to_vec(),
                mode: 6,
                scp,
                sequence_counter: body[12..14].to_vec(),
            }),
            other => bail!("card speaks SCP{other:02X}, which this loader does not implement"),
        }
    }

    /// Test static keys against the card's cryptogram without authenticating. The card never sees a
    /// wrong host cryptogram, so no retry counter moves.
    pub fn check<T: Transport>(card: &mut T, keys: &StaticKeys) -> Result<KeyCheck> {
        let challenge = Self::challenge(card)?;
        let matches = match keys {
            StaticKeys::Scp03(k) if challenge.scp == 0x03 => {
                let expected = SessionKeys::card_cryptogram(
                    k, &challenge.host_challenge, &challenge.card_challenge, challenge.mode);
                expected == challenge.card_cryptogram
            }
            StaticKeys::Scp02(k) if challenge.scp == 0x02 => {
                let expected = Scp02Session::card_cryptogram(
                    k, &challenge.host_challenge, &challenge.sequence_counter,
                    &challenge.card_challenge);
                expected[..] == challenge.card_cryptogram[..]
            }
            StaticKeys::Scp03(_) => bail!("the card speaks SCP02; these are AES keys, it wants 3DES"),
            StaticKeys::Scp02(_) => bail!("the card speaks SCP03; these are 3DES keys, it wants AES"),
        };
        Ok(KeyCheck { matches, challenge })
    }

    /// Ask the card for a challenge and prove we hold the static keys.
    pub fn establish<T: Transport>(card: &mut T, keys: &StaticKeys, security_level: u8) -> Result<Self> {
        let challenge = Self::challenge(card)?;
        match (keys, challenge.scp) {
            (StaticKeys::Scp03(k), 0x03) => Self::establish_scp03(card, k, security_level, challenge),
            (StaticKeys::Scp02(k), 0x02) => Self::establish_scp02(card, k, security_level, challenge),
            (StaticKeys::Scp03(_), 0x02) => bail!("the card speaks SCP02; these are AES keys, supply 3DES"),
            (StaticKeys::Scp02(_), 0x03) => bail!("the card speaks SCP03; these are 3DES keys, supply AES"),
            (_, other) => bail!("unsupported secure channel protocol SCP{other:02X}"),
        }
    }

    fn establish_scp03<T: Transport>(
        card: &mut T,
        keys: &Scp03Keys,
        security_level: u8,
        challenge: CardChallenge,
    ) -> Result<Self> {
        let mode = challenge.mode;
        let expected = SessionKeys::card_cryptogram(
            keys, &challenge.host_challenge, &challenge.card_challenge, mode);
        if !constant_time_eq(&expected, &challenge.card_cryptogram) {
            bail!("card cryptogram did not verify: the static keys are not the card's");
        }

        let session_keys = SessionKeys::derive(
            keys, &challenge.host_challenge, &challenge.card_challenge, mode);
        let host_cryptogram = SessionKeys::host_cryptogram(
            keys, &challenge.host_challenge, &challenge.card_challenge, mode);

        let mut session = Self {
            channel: Channel::Scp03(session_keys),
            mode,
            scp: 0x03,
            sd_aid: hex::decode("A000000003000000").expect("constant AID"),
        };

        let mut data = host_cryptogram;
        let header = [0x84u8, 0x82, security_level, 0x00, (data.len() + mode) as u8];
        let mut apdu = header.to_vec();
        apdu.extend_from_slice(&data);
        let mac = match &mut session.channel {
            Channel::Scp03(k) => k.c_mac(&apdu),
            Channel::Scp02(_) => unreachable!(),
        };
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

    fn establish_scp02<T: Transport>(
        card: &mut T,
        keys: &Scp02Keys,
        security_level: u8,
        challenge: CardChallenge,
    ) -> Result<Self> {
        let expected = Scp02Session::card_cryptogram(
            keys, &challenge.host_challenge, &challenge.sequence_counter, &challenge.card_challenge);
        if !constant_time_eq(&expected, &challenge.card_cryptogram) {
            bail!("card cryptogram did not verify: the static keys are not the card's");
        }

        let host_cryptogram = Scp02Session::host_cryptogram(
            keys, &challenge.host_challenge, &challenge.sequence_counter, &challenge.card_challenge);
        let session_keys = Scp02Session::derive(keys, &challenge.sequence_counter);

        let mut session = Self {
            channel: Channel::Scp02(session_keys),
            mode: 8,
            scp: 0x02,
            sd_aid: hex::decode("A000000003000000").expect("constant AID"),
        };

        let mut data = host_cryptogram.to_vec();
        let header = [0x84u8, 0x82, security_level, 0x00, 16];
        let mut apdu = header.to_vec();
        apdu.extend_from_slice(&data);
        let mac = match &mut session.channel {
            Channel::Scp02(k) => k.c_mac(&apdu),
            Channel::Scp03(_) => unreachable!(),
        };
        data.extend_from_slice(&mac);
        let cmd = Command::new(0x84, 0x82, security_level, 0x00).data(data).le(0x00).encode();
        let resp = card.transmit(&cmd).context("EXTERNAL AUTHENTICATE")?;
        let response = Response::from_bytes(&resp)?;
        if !response.is_ok() {
            bail!("card rejected EXTERNAL AUTHENTICATE: {} ({:04X})",
                  response.describe(), response.status());
        }
        Ok(session)
    }

    /// Wrap a command with a C-MAC. Response protection is not applied: the loader asks for
    /// security level 0x01, which is C-MAC only, so the card answers in the clear.
    pub fn wrap(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
        let mcla = (cla & 0xF0) | 0x04;
        match &mut self.channel {
            Channel::Scp03(keys) => {
                let lc = data.len() + self.mode;
                let mut apdu = vec![mcla, ins, p1, p2, lc as u8];
                apdu.extend_from_slice(data);
                let mac = keys.c_mac(&apdu);
                apdu.extend_from_slice(&mac[..self.mode]);
                if let Some(le) = le {
                    apdu.push(le);
                }
                apdu
            }
            Channel::Scp02(keys) => {
                // SCP02 pads the data to a block boundary, and the padding is sent
                let mut padded = data.to_vec();
                padded.push(0x80);
                while padded.len() % 8 != 0 {
                    padded.push(0x00);
                }
                let lc = padded.len() + 8;
                let mut apdu = vec![mcla, ins, p1, p2, lc as u8];
                apdu.extend_from_slice(&padded);
                let mac = keys.c_mac(&apdu);
                apdu.extend_from_slice(&mac);
                if let Some(le) = le {
                    apdu.push(le);
                }
                apdu
            }
        }
    }

    pub fn transmit<T: Transport>(&mut self, card: &mut T, apdu: &[u8]) -> Result<Response> {
        let raw = card.transmit(apdu)?;
        Ok(Response::from_bytes(&raw)?)
    }

    /// Wrap, send, and finish the exchange the card actually wants: 61xx means "ask again with GET
    /// RESPONSE", 6Cxx means the length byte was wrong. Both are normal card behaviour on loads and
    /// neither is an error.
    pub fn execute<T: Transport>(
        &mut self,
        card: &mut T,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: Option<u8>,
    ) -> Result<Response> {
        let apdu = self.wrap(cla, ins, p1, p2, data, le);
        let mut resp = self.transmit(card, &apdu)?;
        loop {
            match resp.status() {
                0x6C00..=0x6CFF => {
                    // the card wants a different Le: fix ours and ask once more
                    let correct = (resp.status() & 0xFF) as u8;
                    let mut retry = apdu.clone();
                    if le.is_some() {
                        *retry.last_mut().expect("Le present") = correct;
                    } else {
                        retry.push(correct);
                    }
                    resp = self.transmit(card, &retry)?;
                }
                0x6100..=0x61FF => {
                    let want = (resp.status() & 0xFF) as u8;
                    let get = [0x00u8, 0xC0, 0x00, 0x00, want];
                    return self.transmit(card, &get);
                }
                _ => break,
            }
        }
        Ok(resp)
    }
}

fn random_challenge() -> Vec<u8> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.to_vec();
        }
    }
    // Never reuse a fixed challenge in anger, but a clock-derived one is still better than zero
    // when /dev/urandom is unavailable, and the card cryptogram check is what actually matters.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    buf.copy_from_slice(&nanos.to_be_bytes()[8..]);
    buf.to_vec()
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
            .field("scp", &self.scp)
            .field("mode", &self.mode)
            .field("keys", &"<derived>")
            .finish()
    }
}
