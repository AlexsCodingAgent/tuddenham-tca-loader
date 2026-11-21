//! GlobalPlatform card management as far as a loader needs it to say "what is on this card".
//!
//! This module is read-only on purpose. Loading, installing and deleting applets come next,
//! and they all sit on the same two primitives that are here: a SELECT of the card manager
//! and a GET STATUS that lists security domains and applications with their life cycle and
//! privileges.

use anyhow::{bail, Result};

use crate::apdu::{Command, Response};
use crate::card::Transport;
use crate::tlv;

/// The issuer security domain every GlobalPlatform card answers to.
pub const ISD_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];

/// GET DATA tags used by the info view.
pub const TAG_CARD_RECOGNITION: u32 = 0x0066;
pub const TAG_CPLC: u32 = 0x9F7F;
pub const TAG_IIN: u32 = 0x0042;
pub const TAG_CARD_IMAGE_NUMBER: u32 = 0x0045;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    pub aid: Vec<u8>,
    pub life_cycle: u8,
    pub privileges: Vec<u8>,
}

impl AppEntry {
    pub fn aid_hex(&self) -> String {
        hex::encode(&self.aid)
    }

    /// Short state word for tables.
    pub fn life_cycle_short(&self) -> &'static str {
        match self.life_cycle {
            0x01 => "INSTALLED",
            0x07 => "SELECTABLE",
            0x0F => "PERSONALIZED",
            0x83 => "LOCKED",
            _ => "OTHER",
        }
    }

    /// The GlobalPlatform life cycle byte, in the words the specification uses.
    pub fn state(&self) -> &'static str {
        match self.life_cycle {
            0x01 => "INSTALLED",
            0x03 => "INSTALLED (install for install done, personalisation pending)",
            0x07 => "SELECTABLE",
            0x0F => "PERSONALIZED",
            0x83 => "LOCKED",
            0x00 | 0xFF => "unknown",
            _ => "other",
        }
    }
}

fn send<T: Transport>(card: &mut T, cmd: Command) -> Result<Response> {
    let raw = card.transmit(&cmd.encode())?;
    let resp = Response::from_bytes(&raw)?;
    if !resp.is_ok() {
        bail!("{:04X}: {}", resp.status(), resp.describe());
    }
    Ok(resp)
}

/// Select the issuer security domain. A card that answers this is GlobalPlatform.
pub fn select_isd<T: Transport>(card: &mut T) -> Result<Response> {
    send(
        card,
        Command::new(0x00, 0xA4, 0x04, 0x00).data(ISD_AID.to_vec()).le(0x00),
    )
}

/// Select any application by AID, used before talking to a non-default security domain.
pub fn select_aid<T: Transport>(card: &mut T, aid: &[u8]) -> Result<Response> {
    send(card, Command::new(0x00, 0xA4, 0x04, 0x00).data(aid.to_vec()).le(0x00))
}

/// GET DATA for one tag. Not every card carries every tag, so a 6A88 is returned as None
/// rather than as a failure: a missing CPLC is a property of the card.
pub fn get_data<T: Transport>(card: &mut T, tag: u32) -> Result<Option<Vec<u8>>> {
    let mut data = Vec::with_capacity(3);
    if tag > 0xFF {
        data.extend_from_slice(&[(tag >> 8) as u8, tag as u8]);
    } else {
        data.push(tag as u8);
    }
    let resp = Response::from_bytes(&card.transmit(
        &Command::new(0x80, 0xCA, (tag >> 8) as u8, tag as u8).data(data).le(0x00).encode(),
    )?)?;
    if resp.status() == 0x6A88 || resp.status() == 0x6A82 {
        return Ok(None);
    }
    if !resp.is_ok() {
        bail!("GET DATA {tag:04X} failed: {:04X} {}", resp.status(), resp.describe());
    }
    Ok(Some(resp.data))
}

/// GET STATUS of issuer security domains or of everything loadable.
/// `isd_only` maps to P2=0x00 (issuer security domains) versus 0x02 (all).
pub fn get_status<T: Transport>(card: &mut T, isd_only: bool) -> Result<Vec<AppEntry>> {
    let p2 = if isd_only { 0x00 } else { 0x02 };
    let resp = send(
        card,
        Command::new(0x80, 0xF2, 0x80, p2).data(vec![0x4F, 0x00]).le(0x00),
    )?;
    Ok(parse_get_status(&resp.data))
}

/// GET STATUS, keeping the name the CLI uses.
pub fn status_of<T: Transport>(card: &mut T, isd_only: bool) -> Result<Vec<AppEntry>> {
    get_status(card, isd_only)
}

/// A GET STATUS response is a sequence of constructed entries, each carrying 4F (AID),
/// 9F70 (life cycle) and C5 (privileges).
pub fn parse_get_status(data: &[u8]) -> Vec<AppEntry> {
    let mut out = Vec::new();
    let Ok(entries) = tlv::parse(data) else { return out };
    for entry in entries {
        let Ok(children) = entry.children() else { continue };
        let Some(aid) = tlv::find(&children, 0x4F) else { continue };
        out.push(AppEntry {
            aid: aid.to_vec(),
            life_cycle: tlv::find(&children, 0x9F70).and_then(|v| v.first().copied()).unwrap_or(0),
            privileges: tlv::find(&children, 0xC5).map(|v| v.to_vec()).unwrap_or_default(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::ScriptedTransport;

    fn entry(aid: &[u8], lc: u8) -> Vec<u8> {
        let mut inner = vec![0x4F, aid.len() as u8];
        inner.extend_from_slice(aid);
        inner.extend_from_slice(&[0x9F, 0x70, 0x01, lc]);
        inner.extend_from_slice(&[0xC5, 0x01, 0x9E]);
        tlv::encode(0xE3, &inner)
    }

    #[test]
    fn parses_two_security_domains() {
        let mut body = entry(&ISD_AID, 0x0F);
        body.extend_from_slice(&entry(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00], 0x07));
        let apps = parse_get_status(&body);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].aid, ISD_AID.to_vec());
        assert_eq!(apps[0].state(), "PERSONALIZED");
        assert_eq!(apps[1].state(), "SELECTABLE");
        assert_eq!(apps[1].privileges, vec![0x9E]);
    }

    #[test]
    fn a_garbage_response_yields_no_entries_instead_of_panicking() {
        assert!(parse_get_status(&[0xE3, 0x40, 0x01]).is_empty());
    }

    #[test]
    fn select_isd_sends_the_expected_apdu() {
        let cmd = Command::new(0x00, 0xA4, 0x04, 0x00).data(ISD_AID.to_vec()).le(0x00).encode();
        let mut card = ScriptedTransport { scripted: vec![(cmd, vec![0x6F, 0x00, 0x90, 0x00])], sent: vec![] };
        select_isd(&mut card).unwrap();
        assert_eq!(card.sent.len(), 1);
    }

    #[test]
    fn a_missing_cplc_is_none_not_an_error() {
        let cmd = Command::new(0x80, 0xCA, 0x9F, 0x7F)
            .data(vec![0x9F, 0x7F])
            .le(0x00)
            .encode();
        let mut card = ScriptedTransport { scripted: vec![(cmd, vec![0x6A, 0x88])], sent: vec![] };
        assert_eq!(get_data(&mut card, TAG_CPLC).unwrap(), None);
    }

    #[test]
    fn a_security_failure_surfaces_as_an_error() {
        let cmd = Command::new(0x00, 0xA4, 0x04, 0x00).data(ISD_AID.to_vec()).le(0x00).encode();
        let mut card = ScriptedTransport { scripted: vec![(cmd, vec![0x69, 0x82])], sent: vec![] };
        let err = select_isd(&mut card).unwrap_err().to_string();
        assert!(err.contains("6982"), "{err}");
    }
}
