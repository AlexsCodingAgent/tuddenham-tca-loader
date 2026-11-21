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
        Ok(Self { card, reader: chosen })
    }
}

impl Transport for PcscTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let mut buf = [0u8; 4096];
        let resp = self
            .card
            .transmit(command, &mut buf)
            .context("card refused the command (was it removed?)")?;
        Ok(resp.to_vec())
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
