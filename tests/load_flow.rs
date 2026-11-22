//! A card that is not a card: it answers SCP03 with the right crypto and records every command.
//!
//! The point is to exercise the whole load sequence - challenge, key derivation, cryptogram check,
//! EXTERNAL AUTHENTICATE, INSTALL [for load], every LOAD block, INSTALL [for install] - without
//! hardware, and to prove the bytes that reach the card reconstruct the CAP file exactly.

use anyhow::Result;
use tuddenham_tca_loader::cap::CapFile;
use tuddenham_tca_loader::card::Transport;
use tuddenham_tca_loader::load::{load, LoadOptions};
use tuddenham_tca_loader::scp03::{Scp03Keys, SessionKeys, TEST_KEYS};
use tuddenham_tca_loader::session::Session;

#[derive(Default)]
struct MockCard {
    host_challenge: Vec<u8>,
    card_challenge: Vec<u8>,
    commands: Vec<Vec<u8>>,
    load_buffer: Vec<u8>,
    installed: Vec<Vec<u8>>,
    next_block: u8,
    authenticated: bool,
    session: Option<SessionKeys>,
    last_mac: Vec<u8>,
}

impl MockCard {
    fn ok() -> Vec<u8> {
        vec![0x90, 0x00]
    }

    fn error(sw1: u8, sw2: u8) -> Vec<u8> {
        vec![sw1, sw2]
    }
}

impl Transport for MockCard {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.commands.push(command.to_vec());
        if command.len() < 4 {
            return Ok(Self::error(0x67, 0x00));
        }
        let (cla, ins, p1, p2) = (command[0], command[1], command[2], command[3]);
        let data: &[u8] = if command.len() > 5 {
            let lc = command[4] as usize;
            &command[5..5 + lc.min(command.len().saturating_sub(5))]
        } else {
            &[]
        };

        // unwrap the C-MAC: the loader sets bit 0x04 in CLA on secured commands
        if cla & 0x04 != 0 && ins != 0x82 {
            // strip the trailing MAC so the payload checks below see plain data
            let mac_len = self.session.as_ref().map(|_| 8).unwrap_or(0);
            let body = &data[..data.len().saturating_sub(mac_len)];
            return self.handle(ins, p1, p2, body);
        }
        self.handle(ins, p1, p2, data)
    }

    fn describe(&self) -> String {
        "mock card".into()
    }
}

impl MockCard {
    fn handle(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        match ins {
            0x50 => {
                // INITIALIZE UPDATE: 10 bytes of key diversification, KVN, SCP03, i, challenges
                self.host_challenge = data.to_vec();
                self.card_challenge = vec![0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
                let cryptogram = SessionKeys::card_cryptogram(
                    &TEST_KEYS, &self.host_challenge, &self.card_challenge, 8);
                let mut out = vec![0u8; 10];
                out.extend_from_slice(&[0x01, 0x03, 0x70]);
                out.extend_from_slice(&self.card_challenge);
                out.extend_from_slice(&cryptogram);
                out.extend_from_slice(&[0x90, 0x00]);
                self.session = Some(SessionKeys::derive(
                    &TEST_KEYS, &self.host_challenge, &self.card_challenge, 8));
                Ok(out)
            }
            0x82 => {
                // EXTERNAL AUTHENTICATE: check the host cryptogram
                let keys = self.session.as_ref().expect("session after INITIALIZE UPDATE");
                let expected = SessionKeys::host_cryptogram(
                    &TEST_KEYS, &self.host_challenge, &self.card_challenge, 8);
                if data.len() < 8 || data[..8] != expected[..] {
                    return Ok(Self::error(0x63, 0x00));
                }
                let mut keys = keys.clone();
                let header = [0x84u8, 0x82, p1, p2, (8 + 8) as u8];
                let mut mac_input = header.to_vec();
                mac_input.extend_from_slice(&expected);
                let mac = keys.c_mac(&mac_input);
                self.last_mac = mac.to_vec();
                if data.len() >= 16 && data[8..16] != mac[..8] {
                    return Ok(Self::error(0x69, 0x85));
                }
                self.authenticated = true;
                Ok(Self::ok())
            }
            0xE6 if p1 == 0x02 => {
                // INSTALL [for load]: remember the AID being prepared
                self.installed.push(data.to_vec());
                self.next_block = 0;
                self.load_buffer.clear();
                Ok(Self::ok())
            }
            0xE8 => {
                if !self.authenticated {
                    return Ok(Self::error(0x69, 0x82));
                }
                if p2 != self.next_block {
                    return Ok(Self::error(0x69, 0x85)); // wrong block number
                }
                self.next_block = self.next_block.wrapping_add(1);
                let mut payload = data.to_vec();
                if p1 & 0x80 == 0 && p1 != 0x00 {
                    return Ok(Self::error(0x6A, 0x80));
                }
                if !self.load_buffer.is_empty() || payload.first() == Some(&0xC4) {
                    // strip the C4 tag and length from the first block only
                    if payload.first() == Some(&0xC4) {
                        let (len, used) = match payload[1] {
                            0x81 => (payload[2] as usize, 3),
                            0x82 => (((payload[2] as usize) << 8) | payload[3] as usize, 4),
                            n => (n as usize, 2),
                        };
                        let _ = len;
                        payload.drain(..used);
                    }
                }
                self.load_buffer.extend_from_slice(&payload);
                Ok(Self::ok())
            }
            0xE6 if p1 == 0x0C || p1 == 0x04 => {
                self.installed.push(data.to_vec());
                Ok(Self::ok())
            }
            0xE4 => {
                self.installed.push(data.to_vec());
                Ok(Self::ok())
            }
            _ => Ok(Self::error(0x6D, 0x00)),
        }
    }
}

fn sample_cap(load_len: usize) -> CapFile {
    let mut load_file = Vec::with_capacity(load_len + 16);
    // a plausible component stream: Header then a body, all bytes distinct enough to spot loss
    load_file.extend_from_slice(&[0x01, 0x00, 0x08, 0xDE, 0xCA, 0xFF, 0xED, 0x02, 0x02, 0x00, 0x07]);
    for i in 0..load_len {
        load_file.push((i % 251) as u8);
    }
    CapFile {
        package_aid: hex::decode("A0000000620101").unwrap(),
        version: (1, 0),
        cap_version: (3, 0),
        load_file,
        components: Vec::new(),
        applets: vec![tuddenham_tca_loader::cap::Applet {
            aid: hex::decode("A000000062010101").unwrap(),
            install_offset: 10,
        }],
    }
}

#[test]
fn a_whole_load_round_trips_through_a_card() {
    let cap = sample_cap(600);
    let mut card = MockCard::default();
    let mut session = Session::establish(&mut card, &TEST_KEYS, 0x01).expect("channel opens");
    assert_eq!(session.mode, 8, "the mock card offers S8");

    let mut progress_calls = 0usize;
    let result = load(
        &mut card,
        &mut session,
        &cap,
        &LoadOptions { block_size: 245, ..Default::default() },
        |_, _| progress_calls += 1,
    )
    .expect("load completes");

    // the bytes the card received must reconstruct the CAP's load file exactly
    assert_eq!(card.load_buffer, cap.load_file, "load file arrived intact");
    assert_eq!(result.bytes, cap.blocks(245).iter().map(|b| b.len()).sum::<usize>());
    assert!(result.blocks > 1, "the sample spans several blocks");
    assert_eq!(progress_calls, result.blocks);
    assert_eq!(result.instance_aid.as_deref(), Some("a000000062010101"));
}

#[test]
fn the_first_block_carries_c4_and_the_rest_do_not() {
    let cap = sample_cap(400);
    let mut card = MockCard::default();
    let mut session = Session::establish(&mut card, &TEST_KEYS, 0x01).unwrap();
    load(&mut card, &mut session, &cap, &LoadOptions::default(), |_, _| {}).unwrap();

    let loads: Vec<&Vec<u8>> = card.commands.iter()
        .filter(|c| c.len() > 1 && c[1] == 0xE8)
        .collect();
    assert!(loads.len() >= 2);
    assert_eq!(loads[0][5], 0xC4, "first LOAD payload starts with the C4 tag");
    for later in &loads[1..] {
        assert_ne!(later[5], 0xC4, "only the first block is tagged");
    }
    // the last block is marked in P1 bit 8
    assert_eq!(loads.last().unwrap()[2] & 0x80, 0x80);
}

#[test]
fn install_names_the_domain_and_the_instance() {
    let cap = sample_cap(120);
    let mut card = MockCard::default();
    let mut session = Session::establish(&mut card, &TEST_KEYS, 0x01).unwrap();
    load(&mut card, &mut session, &cap, &LoadOptions { privileges: 0, ..Default::default() }, |_, _| {})
        .unwrap();

    let installs: Vec<&Vec<u8>> = card.commands.iter()
        .filter(|c| c.len() > 1 && c[1] == 0xE6)
        .collect();
    assert_eq!(installs.len(), 2, "INSTALL [for load] then INSTALL [for install]");
    let for_load = installs[0];
    assert_eq!(for_load[2], 0x02);
    // data begins with the package AID, length prefixed
    assert_eq!(for_load[5], 0x07);
    assert_eq!(&for_load[6..13], &cap.package_aid[..]);

    let for_install = installs[1];
    assert_eq!(for_install[2], 0x0C, "install and make selectable");
}

#[test]
fn a_card_that_skips_install_for_load_is_reported_not_ignored() {
    struct Refusing;
    impl Transport for Refusing {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            match command[1] {
                0x50 => {
                    let host = &command[5..13];
                    let card = [0x08u8, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
                    let mut out = vec![0u8; 10];
                    out.extend_from_slice(&[0x01, 0x03, 0x70]);
                    out.extend_from_slice(&card);
                    out.extend_from_slice(&SessionKeys::card_cryptogram(&TEST_KEYS, host, &card, 8));
                    out.extend_from_slice(&[0x90, 0x00]);
                    Ok(out)
                }
                0x82 => Ok(vec![0x90, 0x00]),
                0xE6 => Ok(vec![0x69, 0x85]),
                _ => Ok(vec![0x90, 0x00]),
            }
        }
        fn describe(&self) -> String { "refusing card".into() }
    }

    let cap = sample_cap(50);
    let mut card = Refusing;
    let mut session = Session::establish(&mut card, &TEST_KEYS, 0x01).unwrap();
    let err = load(&mut card, &mut session, &cap, &LoadOptions::default(), |_, _| {})
        .unwrap_err()
        .to_string();
    assert!(err.contains("INSTALL [for load]"), "{err}");
    assert!(err.contains("6985"), "{err}");
}
