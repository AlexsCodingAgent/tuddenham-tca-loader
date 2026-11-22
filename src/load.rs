//! The load sequence: INSTALL [for load], LOAD blocks, INSTALL [for install and make selectable].
//!
//! Order matters and so does state: a card that receives LOAD before INSTALL [for load] answers
//! 6985, and one that receives LOAD after a failed install has to be reset before the next attempt.
//! This module drives the three steps and stops at the first non-9000, reporting which step failed
//! rather than returning a bare status word.

use anyhow::{bail, Result};

use crate::apdu::Response;
use crate::cap::CapFile;
use crate::card::Transport;
use crate::commands;
use crate::session::Session;

#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Bytes per LOAD command, before the wrapper. Cards commonly take 245 or 255.
    pub block_size: usize,
    pub privileges: u32,
    pub params: Vec<u8>,
    pub make_selectable: bool,
    /// Overrides the application instance AID, which otherwise defaults to the applet's own.
    pub instance_aid: Option<Vec<u8>>,
    /// Load File Data Block Hash, if the security domain wants one.
    pub hash: Option<Vec<u8>>,
    /// Skip the final INSTALL, leaving a load file on the card with no instance.
    pub prepare_only: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            block_size: 245,
            privileges: 0,
            params: Vec::new(),
            make_selectable: true,
            instance_aid: None,
            hash: None,
            prepare_only: false,
        }
    }
}

#[derive(Debug)]
pub struct LoadResult {
    pub package_aid: String,
    pub instance_aid: Option<String>,
    pub blocks: usize,
    pub bytes: usize,
}

pub fn load<T: Transport>(
    card: &mut T,
    session: &mut Session,
    cap: &CapFile,
    opts: &LoadOptions,
    mut progress: impl FnMut(usize, usize),
) -> Result<LoadResult> {
    let sd_aid = current_selected_aid();
    let package_aid = cap.package_aid.clone();

    // 1. INSTALL [for load] reserves the load file on the card
    let data = commands::install_for_load(&package_aid, &sd_aid, opts.hash.as_deref());
    let resp = session.execute(card, 0x80, 0xE6, 0x02, 0x00, &data, Some(0x00))?;
    expect_ok(&resp, "INSTALL [for load]")?;

    // 2. LOAD every block, marking the last one
    let blocks = cap.blocks(opts.block_size);
    let total = blocks.len();
    let mut sent = 0usize;
    for (index, payload) in blocks.iter().enumerate() {
        let last = index + 1 == total;
        let p1 = if last { 0x80 } else { 0x00 };
        if index > 0xFF {
            bail!("load file needs {} blocks, a card accepts 256", total);
        }
        let resp = session.execute(card, 0x80, 0xE8, p1, index as u8, payload, None)?;
        expect_ok(&resp, &format!("LOAD block {}", index + 1))?;
        sent += payload.len();
        progress(index + 1, total);
    }

    if opts.prepare_only {
        return Ok(LoadResult {
            package_aid: hex::encode(&package_aid),
            instance_aid: None,
            blocks: total,
            bytes: sent,
        });
    }

    // 3. INSTALL [for install] or [for install and make selectable]
    let module_aid = cap.module_aid().to_vec();
    let instance = opts.instance_aid.clone().unwrap_or_else(|| cap.default_instance_aid().to_vec());
    let data = commands::install_for_install(
        &package_aid, &module_aid, &instance, opts.privileges, &opts.params,
    );
    let p1 = if opts.make_selectable { 0x0C } else { 0x04 };
    let resp = session.execute(card, 0x80, 0xE6, p1, 0x00, &data, Some(0x00))?;
    expect_ok(&resp, "INSTALL [for install]")?;

    Ok(LoadResult {
        package_aid: hex::encode(&package_aid),
        instance_aid: Some(hex::encode(&instance)),
        blocks: total,
        bytes: sent,
    })
}

pub fn delete<T: Transport>(
    card: &mut T,
    session: &mut Session,
    aid: &[u8],
    related: bool,
) -> Result<Response> {
    let data = commands::delete(&[aid]);
    let p2 = if related { 0x80 } else { 0x00 };
    let resp = session.execute(card, 0x80, 0xE4, 0x00, p2, &data, Some(0x00))?;
    expect_ok(&resp, "DELETE")?;
    Ok(resp)
}

/// The security domain the session authenticated to. Kept here because every install names the
/// domain that receives the load file, and the ISS uses its own AID for that.
fn current_selected_aid() -> Vec<u8> {
    hex::decode("A000000003000000").expect("constant AID")
}

fn expect_ok(resp: &Response, step: &str) -> Result<()> {
    if resp.is_ok() {
        return Ok(());
    }
    let sw = resp.status();
    let hint = match sw {
        0x6985 => Some("no INSTALL [for load] preceded this, or the card is in a state that refuses it"),
        0x6A84 => Some("not enough memory on the card"),
        0x6A80 => Some("wrong data: check the AIDs and the install parameters"),
        0x6D00 => Some("the card does not implement this command"),
        0x6982 => Some("the security level is too low for this command"),
        _ => None,
    };
    match hint {
        Some(hint) => bail!("{step} failed: {} ({:04X}): {hint}", resp.describe(), sw),
        None => bail!("{step} failed: {} ({:04X})", resp.describe(), sw),
    }
}
