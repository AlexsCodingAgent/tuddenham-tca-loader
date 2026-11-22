//! Transports.
//!
//! Everything above this module sends an APDU and gets bytes back, which is deliberate: the
//! same command layer has to work over PC/SC here, and later over CAT-TP or a SIM-over-IP
//! relay, without the loader changing. Keeping the trait this small is what makes that
//! possible.

use anyhow::{Context as _, Result};

pub trait Transport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>>;
    fn describe(&self) -> String;
}

/// A card in a contact or contactless reader, driven by pcsc-lite.
pub struct PcscTransport {
    card: pcsc::Card,
    reader: String,
}

impl PcscTransport {
    /// Send a command and collect the whole response, following 61xx with GET RESPONSE.
    /// Reconnects once if the card drops the transaction, which happens after a refused select.
    pub fn transmit_full(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut current = command.to_vec();
        let mut buf = [0u8; 4096];
        for _ in 0..8 {
            let raw = match self.card.transmit(&current, &mut buf) {
                Ok(raw) => raw.to_vec(),
                Err(_) => {
                    // reconnect on the protocol the card actually negotiated: asking for ANY
                    // again is what pcsc rejects with "protocols are incompatible"
                    let mut atr = [0u8; 64];
                    let mut names = [0u8; 4096];
                    let protocols = match self.card.status2(&mut atr, &mut names).ok()
                        .and_then(|s| s.protocol2()) {
                        Some(pcsc::Protocol::T0) => pcsc::Protocols::T0,
                        Some(pcsc::Protocol::T1) => pcsc::Protocols::T1,
                        _ => pcsc::Protocols::ANY,
                    };
                    let _ = self.card.reconnect(pcsc::ShareMode::Shared, protocols,
                                                pcsc::Disposition::LeaveCard);
                    let again = self.card.transmit(&current, &mut buf)?;
                    again.to_vec()
                }
            };
            if raw.len() < 2 {
                return Ok(raw);
            }
            let (sw1, sw2) = (raw[raw.len() - 2], raw[raw.len() - 1]);
            out.extend_from_slice(&raw[..raw.len() - 2]);
            if sw1 == 0x61 {
                current = vec![0x00, 0xC0, 0x00, 0x00, sw2];
                continue;
            }
            out.extend_from_slice(&[sw1, sw2]);
            return Ok(out);
        }
        Ok(out)
    }

    /// The ATR of the card in this reader, hex encoded.
    pub fn atr_hex(&self) -> Result<String> {
        let mut atr = [0u8; 64];
        let mut names = [0u8; 4096];
        let status = self.card.status2(&mut atr, &mut names)
            .map_err(|e| anyhow::anyhow!("reading the ATR: {e}"))?;
        Ok(hex::encode(status.atr()).to_uppercase())
    }

    /// Open the first reader that holds a card, or the named one.
    pub fn open(reader: Option<&str>) -> Result<Self> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)
            .context("no PC/SC service: is pcscd running and a reader attached?")?;
        let mut buf = [0u8; 2048];
        let mut names: Vec<String> = Vec::new();
        for reader in ctx.list_readers(&mut buf).context("listing readers")? {
            names.push(reader.to_string_lossy().into_owned());
        }
        let chosen = match reader {
            Some(name) => names
                .iter()
                .find(|n| n.contains(name))
                .cloned()
                .with_context(|| format!("no reader matching {name:?}; saw {names:?}"))?,
            None => names.into_iter().next().context("no readers attached")?,
        };
        let cname = std::ffi::CString::new(chosen.clone())?;
        let card = ctx
            .connect(&cname, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .with_context(|| format!("cannot connect to a card in {chosen}"))?;
        // A cold reset puts the card in a known state: a Card Manager that has already seen an
        // authentication (or is mid-transaction) refuses INITIALIZE UPDATE with 6882 otherwise.
        let mut card = card;
        let _ = card.reconnect(pcsc::ShareMode::Shared, pcsc::Protocols::ANY,
                               pcsc::Disposition::ResetCard);
        Ok(Self { card, reader: chosen })
    }
}

impl Transport for PcscTransport {
    /// Every exchange is finished here, at the transport, so callers never see a bare 61xx:
    /// the card asking for GET RESPONSE is a card that has data to give, not an error.
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.transmit_full(command)
    }

    fn describe(&self) -> String {
        self.reader.clone()
    }
}

/// An in-memory card, so the command layer can be tested without hardware.
pub struct ScriptedTransport {
    pub scripted: Vec<(Vec<u8>, Vec<u8>)>,
    pub sent: Vec<Vec<u8>>,
}

impl Transport for ScriptedTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.sent.push(command.to_vec());
        for (expected, response) in &self.scripted {
            if expected == command {
                return Ok(response.clone());
            }
        }
        Ok(vec![0x6D, 0x00])
    }

    fn describe(&self) -> String {
        "scripted card".into()
    }
}
