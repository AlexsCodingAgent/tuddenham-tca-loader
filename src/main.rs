use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tuddenham_tca_loader::{card::PcscTransport, gp, Transport};

#[derive(Parser)]
#[command(name = "tca-loader", version, about = "Inspect and manage applications on a UICC or eUICC")]
struct Cli {
    /// Reader name fragment; the first reader with a card is used when omitted.
    #[arg(long, global = true)]
    reader: Option<String>,
    /// Static keys as enc:mac:dek in hex. Prefer --keys-file or the environment: a key on the
    /// command line lands in shell history.
    #[arg(long, global = true)]
    keys: Option<String>,
    /// File holding the keys, one line, enc:mac:dek in hex, or the same with comments.
    #[arg(long, global = true)]
    keys_file: Option<String>,
    /// Force the secure channel the keys belong to: 02 (3DES) or 03 (AES). Guessed from key
    /// length otherwise: 24 bytes means 3DES, 16 means AES.
    #[arg(long, global = true)]
    scp: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List PC/SC readers and which of them hold a card.
    Readers,
    /// Select the issuer security domain and print what the card says about itself.
    Info,
    /// Open an SCP03 secure channel, then list what the card holds through it.
    Auth {
        /// GlobalPlatform test keys (40..4F, 50..5F, 60..6F) instead of real ones.
        #[arg(long, default_value_t = true)]
        test_keys: bool,
        /// Security level: 01 C-MAC only, 33 C-MAC plus C-DECRYPTION and response protection.
        #[arg(long, value_parser = parse_hex_u8, default_value = "01")]
        security_level: u8,
        /// AID to select instead of the default issuer security domain.
        #[arg(long)]
        aid: Option<String>,
    },
    /// List security domains and applications with life cycle and privileges.
    Status {
        /// Only issuer security domains, not every application.
        #[arg(long)]
        isd_only: bool,
    },
    /// Work out what the card is when the security domain does not answer at the usual AID:
    /// ATR, the EF_DIR application list, and a sweep of known security domain AIDs.
    Probe,
    /// Try the keys against the card without authenticating, so a wrong key costs no attempt.
    Check {
        /// Security domain AID; the standard issuer domain is the default.
        #[arg(long)]
        sd: Option<String>,
    },
    /// Walk the registry over an authenticated channel: what is installed, in what state.
    Audit {
        /// Security domain AID; the standard issuer domain is the default.
        #[arg(long)]
        sd: Option<String>,
    },
    /// Write everything the card discloses without keys to one file, for a support ticket.
    Dump {
        /// Where to write the report.
        #[arg(long, default_value = "card-report.txt")]
        out: String,
    },
    /// Read and decode the key information template: which key sets exist, of what type.
    Keys {
        /// Security domain AID; the standard issuer domain is the default.
        #[arg(long)]
        sd: Option<String>,
    },
    /// Send a raw APDU, hex, and print the response. For working out what a card wants.
    Raw {
        /// Command APDU in hex.
        apdu: String,
        /// Select this AID first, hex.
        #[arg(long)]
        select: Option<String>,
    },
    /// Read a CAP file and print what a card would be sent.
    Cap {
        /// Path to the .cap file.
        file: String,
        /// Bytes per LOAD block, used only to report the block count.
        #[arg(long, default_value_t = 245)]
        block_size: usize,
    },
    /// Load a CAP file over an SCP03 channel and install it.
    Load {
        /// Path to the .cap file.
        file: String,
        /// Security domain AID to authenticate to; the issuer domain is the default.
        #[arg(long)]
        sd: Option<String>,
        /// Application privileges as a hex bit field.
        #[arg(long, default_value = "0")]
        privileges: String,
        /// Applet install parameters, hex.
        #[arg(long)]
        params: Option<String>,
        /// Bytes per LOAD command.
        #[arg(long, default_value_t = 245)]
        block_size: usize,
        /// Application instance AID; the applet's own AID is the default.
        #[arg(long)]
        instance_aid: Option<String>,
        /// Load the file but do not install an instance.
        #[arg(long)]
        no_install: bool,
        /// Install without making the application selectable.
        #[arg(long)]
        not_selectable: bool,
    },
    /// Delete an application, load file or security domain by AID.
    Delete {
        /// AID to delete, hex.
        aid: String,
        /// Also delete the objects that depend on it.
        #[arg(long)]
        related: bool,
        /// Security domain AID to authenticate to.
        #[arg(long)]
        sd: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Readers => list_readers(),
        Command::Info => info(cli.reader.as_deref()),
        Command::Auth { test_keys: _, security_level, aid } =>
            auth(cli.reader.as_deref(), &cli.keys, &cli.keys_file, &cli.scp, security_level, aid),
        Command::Status { isd_only } => status(cli.reader.as_deref(), isd_only),
        Command::Probe => probe(cli.reader.as_deref()),
        Command::Keys { sd } => keys(cli.reader.as_deref(), sd),
        Command::Raw { apdu, select } => raw(cli.reader.as_deref(), &apdu, select),
        Command::Cap { file, block_size } => cap_info(&file, block_size),
        Command::Load { file, sd, privileges, params, block_size, instance_aid, no_install,
                        not_selectable } =>
            load_cap(cli.reader.as_deref(), &file, sd, &privileges, params, block_size,
                     instance_aid, no_install, not_selectable, &cli.keys, &cli.keys_file, &cli.scp),
        Command::Delete { aid, related, sd } =>
            delete(cli.reader.as_deref(), &aid, related, sd, &cli.keys, &cli.keys_file, &cli.scp),
        Command::Audit { sd } =>
            audit(cli.reader.as_deref(), sd, &cli.keys, &cli.keys_file, &cli.scp),
        Command::Dump { out } => dump(cli.reader.as_deref(), &out),
        Command::Check { sd } =>
            check(cli.reader.as_deref(), sd, &cli.keys, &cli.keys_file, &cli.scp),
    }
}

fn parse_hex_u8(s: &str) -> std::result::Result<u8, String> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex_bytes(spec: &str) -> Result<Vec<u8>> {
    hex::decode(spec.replace(' ', "").trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("not hex: {e}"))
}

/// Keys come from --keys, then --keys-file, then TCA_LOADER_KEYS, then the GlobalPlatform test
/// keys. The order matters: the least exposed source wins.
fn resolve_keys(spec: &Option<String>, file: &Option<String>, scp: &Option<String>)
    -> Result<tuddenham_tca_loader::session::StaticKeys> {
    if let Some(spec) = spec {
        return parse_keys(spec, scp.as_deref());
    }
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading keys from {path}"))?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            return parse_keys(line, scp.as_deref());
        }
        anyhow::bail!("{path} holds no key line");
    }
    if let Ok(spec) = std::env::var("TCA_LOADER_KEYS") {
        if !spec.trim().is_empty() {
            return parse_keys(&spec, scp.as_deref());
        }
    }
    Ok(tuddenham_tca_loader::session::StaticKeys::Scp03(
        tuddenham_tca_loader::scp03::TEST_KEYS))
}

fn parse_keys(spec: &str, scp: Option<&str>) -> Result<tuddenham_tca_loader::session::StaticKeys> {
    use tuddenham_tca_loader::scp02::Scp02Keys;
    use tuddenham_tca_loader::scp03::Scp03Keys;
    use tuddenham_tca_loader::session::StaticKeys;

    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        anyhow::bail!("keys must be enc:mac:dek, hex, all three the same length");
    }
    let mut keys: Vec<Vec<u8>> = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        keys.push(hex::decode(part.replace(' ', ""))
            .map_err(|e| anyhow::anyhow!("key {i} is not hex: {e}"))?);
    }
    let length = keys[0].len();
    if keys.iter().any(|k| k.len() != length) {
        anyhow::bail!("all three keys must be the same length");
    }
    let protocol = match scp {
        Some("02") => 2,
        Some("03") => 3,
        Some(other) => anyhow::bail!("--scp must be 02 or 03, not {other}"),
        None => if length == 24 { 2 } else { 3 },
    };
    match (protocol, length) {
        (3, 16) => Ok(StaticKeys::Scp03(Scp03Keys {
            enc: keys[0].clone().try_into().expect("16"),
            mac: keys[1].clone().try_into().expect("16"),
            dek: keys[2].clone().try_into().expect("16"),
        })),
        (3, other) => anyhow::bail!("SCP03 keys are 16 bytes, these are {other}"),
        (2, 16 | 24) => Ok(StaticKeys::Scp02(Scp02Keys {
            enc: keys[0].clone(),
            mac: keys[1].clone(),
            dek: keys[2].clone(),
        })),
        (2, other) => anyhow::bail!("SCP02 keys are 16 or 24 bytes, these are {other}"),
        _ => unreachable!(),
    }
}

fn auth(reader: Option<&str>, keys: &Option<String>, keys_file: &Option<String>,
        scp: &Option<String>, security_level: u8, aid: Option<String>) -> Result<()> {
    use tuddenham_tca_loader::session::Session;

    let static_keys = resolve_keys(keys, keys_file, scp)?;
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());

    match aid {
        Some(spec) => {
            let bytes = hex::decode(spec.replace(' ', ""))
                .map_err(|e| anyhow::anyhow!("AID is not hex: {e}"))?;
            let resp = gp::select_aid(&mut card, &bytes)?;
            if !resp.is_ok() {
                anyhow::bail!("selecting {spec} failed: {} ({:04X})", resp.describe(), resp.status());
            }
            println!("selected {spec}");
        }
        None => {
            gp::select_isd(&mut card)?;
            println!("issuer security domain selected");
        }
    }

    let mut session = Session::establish(&mut card, &static_keys, security_level)
        .context("opening the secure channel")?;
    println!("secure channel: SCP03, {:?}-byte MAC, security level {:02X}",
             session.mode, security_level);

    // The proof is a wrapped command the card answers only over a valid channel.
    let apdu = session.wrap(0x80, 0xF2, 0x80, 0x00, &[0x4F, 0x00], Some(0x00));
    let resp = session.transmit(&mut card, &apdu)?;
    if !resp.is_ok() {
        anyhow::bail!("GET STATUS over the channel failed: {} ({:04X})",
                      resp.describe(), resp.status());
    }
    let apps = gp::parse_get_status(&resp.data);
    println!("packages over the channel: {}", apps.len());
    println!("{:<32} {:<13} {}", "AID", "STATE", "PRIVILEGES");
    for app in apps {
        println!("{:<32} {:<13} {:02X?}", app.aid_hex(), app.life_cycle_short(), app.privileges);
    }
    Ok(())
}

fn list_readers() -> Result<()> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)
        .context("no PC/SC service: is pcscd running?")?;
    let mut buf = [0u8; 2048];
    let mut any = false;
    for reader in ctx.list_readers(&mut buf).context("listing readers")? {
        let name = reader.to_string_lossy().into_owned();
        let card = ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY);
        let state = match card {
            Ok(c) => {
                let mut atr = [0u8; 33];
                let mut names = [0u8; 33];
                match c.status2(&mut atr, &mut names) {
                    Ok(status) => format!("card present ({})", protocol_name(status.protocol())),
                    Err(_) => "card present".to_string(),
                }
            }
            Err(_) => "empty".to_string(),
        };
        println!("{name}\t{state}");
        any = true;
    }
    if !any {
        println!("no readers attached");
    }
    Ok(())
}

fn protocol_name(p: pcsc::Protocol) -> &'static str {
    match p {
        pcsc::Protocol::T0 => "T=0",
        pcsc::Protocol::T1 => "T=1",
        _ => "other",
    }
}

fn info(reader: Option<&str>) -> Result<()> {
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());
    gp::select_isd(&mut card).context("this card does not answer as a GlobalPlatform card")?;
    println!("issuer security domain: {}", hex::encode(gp::ISD_AID));

    if let Some(data) = gp::get_data(&mut card, gp::TAG_CARD_IMAGE_NUMBER)? {
        println!("card image number: {}", hex::encode(&data));
    }
    if let Some(cplc) = gp::get_data(&mut card, gp::TAG_CPLC)? {
        println!("cplc: {}", hex::encode(&cplc));
        if let Some(serial) = cplc.get(12..16) {
            println!("  chip serial: {}", hex::encode(serial));
        }
    }
    if let Some(iin) = gp::get_data(&mut card, gp::TAG_IIN)? {
        println!("issuer identification number: {}", hex::encode(&iin));
    }
    if let Some(rec) = gp::get_data(&mut card, gp::TAG_CARD_RECOGNITION)? {
        println!("card recognition data: {} bytes", rec.len());
    }
    Ok(())
}

fn status(reader: Option<&str>, isd_only: bool) -> Result<()> {
    let mut card = PcscTransport::open(reader)?;
    let apps = gp::status_of(&mut card, isd_only)?;
    if apps.is_empty() {
        println!("card returned no {} entries", if isd_only { "security domain" } else { "application" });
        return Ok(());
    }
    println!("{:<24} {:<12} {}", "AID", "STATE", "PRIVILEGES");
    for app in apps {
        println!(
            "{:<24} {:<12} {}",
            app.aid_hex(),
            app.life_cycle_short(),
            hex::encode(&app.privileges)
        );
    }
    Ok(())
}

fn cap_info(file: &str, block_size: usize) -> Result<()> {
    use tuddenham_tca_loader::cap::CapFile;

    let cap = CapFile::open(std::path::Path::new(file))?;
    println!("package AID:  {}", hex::encode(&cap.package_aid).to_uppercase());
    println!("package ver:  {}.{}", cap.version.0, cap.version.1);
    println!("CAP version:  {}.{}", cap.cap_version.0, cap.cap_version.1);
    println!("load file:    {} bytes in {} blocks of {}",
             cap.load_file.len(), cap.blocks(block_size).len(), block_size);
    println!("components:");
    for (name, bytes) in cap.components.iter() {
        println!("  {:<14} {:>6} bytes", name, bytes.len());
    }
    if cap.applets.is_empty() {
        println!("applets:      none (library package)");
    } else {
        println!("applets:");
        for applet in cap.applets.iter() {
            println!("  {}  install method at {}", hex::encode(&applet.aid).to_uppercase(),
                     applet.install_offset);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn load_cap(
    reader: Option<&str>,
    file: &str,
    sd: Option<String>,
    privileges: &str,
    params: Option<String>,
    block_size: usize,
    instance_aid: Option<String>,
    no_install: bool,
    not_selectable: bool,
    keys: &Option<String>,
    keys_file: &Option<String>,
    scp: &Option<String>,
) -> Result<()> {
    use tuddenham_tca_loader::cap::CapFile;
    use tuddenham_tca_loader::load::{load, LoadOptions};

    let cap = CapFile::open(std::path::Path::new(file))?;
    let privileges = u32::from_str_radix(privileges.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("privileges are not hex: {e}"))?;
    let params = match params {
        Some(spec) => hex_bytes(&spec)?,
        None => Vec::new(),
    };
    let instance_aid = match instance_aid {
        Some(spec) => Some(hex_bytes(&spec)?),
        None => None,
    };

    println!("package {} ({} bytes, {} blocks)",
             hex::encode(&cap.package_aid).to_uppercase(),
             cap.load_file.len(), cap.blocks(block_size).len());

    let (mut card, mut session) = open_session(reader, sd, keys, keys_file, scp)?;
    let options = LoadOptions {
        block_size,
        privileges,
        params,
        make_selectable: !not_selectable,
        instance_aid,
        hash: None,
        prepare_only: no_install,
    };
    let result = load(&mut card, &mut session, &cap, &options, |done, total| {
        if done == total || done % 10 == 0 {
            print!("\r  LOAD {done}/{total} blocks");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    })?;
    println!();
    println!("loaded {} bytes in {} blocks", result.bytes, result.blocks);
    match result.instance_aid {
        Some(aid) => println!("installed {}", aid.to_uppercase()),
        None => println!("no instance installed (--no-install)"),
    }
    Ok(())
}

fn delete(
    reader: Option<&str>,
    aid: &str,
    related: bool,
    sd: Option<String>,
    keys: &Option<String>,
    keys_file: &Option<String>,
    scp: &Option<String>,
) -> Result<()> {
    let bytes = hex_bytes(aid)?;
    let (mut card, mut session) = open_session(reader, sd, keys, keys_file, scp)?;
    tuddenham_tca_loader::load::delete(&mut card, &mut session, &bytes, related)?;
    println!("deleted {}{}", aid.to_uppercase(), if related { " and its objects" } else { "" });
    Ok(())
}

fn open_session(
    reader: Option<&str>,
    sd: Option<String>,
    keys: &Option<String>,
    keys_file: &Option<String>,
    scp: &Option<String>,
) -> Result<(PcscTransport, tuddenham_tca_loader::session::Session)> {
    use tuddenham_tca_loader::session::Session;

    let static_keys = resolve_keys(keys, keys_file, scp)?;
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());

    let sd_bytes = match sd {
        Some(spec) => {
            let bytes = hex_bytes(&spec)?;
            let resp = gp::select_aid(&mut card, &bytes)?;
            if !resp.is_ok() {
                anyhow::bail!("selecting {spec} failed: {} ({:04X})", resp.describe(), resp.status());
            }
            bytes
        }
        None => {
            gp::select_isd(&mut card)?;
            hex::decode("A000000003000000").expect("constant AID")
        }
    };

    let mut session = Session::establish(&mut card, &static_keys, 0x01)
        .context("opening the secure channel")?;
    session.sd_aid = sd_bytes;
    println!("secure channel: SCP{:02X}, {}-byte MAC, domain {}",
             session.scp, session.mode, hex::encode(&session.sd_aid).to_uppercase());
    Ok((card, session))
}

fn probe(reader: Option<&str>) -> Result<()> {
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());
    println!("ATR:    {}", card.atr_hex().unwrap_or_else(|e| format!("unavailable ({e})")));

    fn sw_of(raw: &[u8]) -> u16 {
        if raw.len() >= 2 {
            u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]])
        } else {
            0
        }
    }

    /// SELECT by AID asking for the FCI back, which is where a GlobalPlatform card states its
    /// secure channel protocol and key version.
    fn select_fci(card: &mut PcscTransport, aid: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut apdu = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        apdu.extend_from_slice(aid);
        apdu.push(0x00);
        let raw = card.transmit_full(&apdu)?;
        let sw = sw_of(&raw);
        Ok((raw[..raw.len().saturating_sub(2)].to_vec(), sw))
    }

    fn walk(data: &[u8], depth: usize) {
        let mut at = 0usize;
        while at + 2 <= data.len() {
            let mut tag = data[at] as u32;
            let mut cursor = at + 1;
            if (data[at] & 0x1F) == 0x1F && cursor < data.len() {
                tag = (tag << 8) | data[cursor] as u32;
                cursor += 1;
            }
            if cursor >= data.len() {
                break;
            }
            let mut len = data[cursor] as usize;
            cursor += 1;
            if len == 0x81 && cursor < data.len() {
                len = data[cursor] as usize;
                cursor += 1;
            } else if len == 0x82 && cursor + 1 < data.len() {
                len = ((data[cursor] as usize) << 8) | data[cursor + 1] as usize;
                cursor += 2;
            }
            if cursor + len > data.len() {
                break;
            }
            let value = &data[cursor..cursor + len];
            let label = match tag {
                0x6F => "FCI",
                0x84 => "DF name (AID)",
                0xA5 => "proprietary",
                0x88 => "SCP i parameter",
                0x9F65 => "max command data",
                0x9F6E => "SCP03 parameters (key version, SCP id, i)",
                0xC0 => "key information template",
                0xC1 => "key information",
                _ => "",
            };
            let printable = value.iter().all(|b| *b >= 0x20 && *b < 0x7F);
            if printable && !value.is_empty() {
                println!("{}{:04X} {:<42} \"{}\"",
                         "  ".repeat(depth), tag, label, String::from_utf8_lossy(value));
            } else {
                println!("{}{:04X} {:<42} {}", "  ".repeat(depth), tag, label, hex::encode(value).to_uppercase());
            }
            if matches!(tag, 0x6F | 0xA5 | 0xC0 | 0xC1) {
                walk(value, depth + 1);
            }
            at = cursor + len;
        }
    }

    println!();
    for (name, aid_hex) in [
        ("GP issuer domain", "A000000003000000"),
        ("GP 2.0.1 issuer domain", "A0000000030000"),
        ("GP card manager", "A000000151000000"),
        ("GP card manager (7 byte)", "A0000001510000"),
        ("GSMA ISD-R", "A0000005591010FFFFFF8901000000"),
        ("USIM", "A0000000871002"),
        ("ISIM", "A0000000871004"),
    ] {
        let bytes = hex::decode(aid_hex).expect("constant");
        let (fci, sw) = select_fci(&mut card, &bytes)?;
        let note = match sw {
            0x9000 => "present",
            0x6A82 => "absent",
            0x6D00 => "no such instruction for this AID",
            _ => "",
        };
        println!("{name:<26} {aid_hex}  {sw:04X} {note}");
        if sw == 0x9000 && !fci.is_empty() {
            walk(&fci, 1);
            // the key information template says which key versions and types exist
            let raw = card.transmit_full(&[0x80u8, 0xCA, 0x00, 0xE0, 0x00])?;
            let sw = sw_of(&raw);
            println!("    GET DATA 00E0 (key information): {sw:04X}");
            if sw == 0x9000 {
                walk(&raw[..raw.len() - 2], 2);
            }
        }
    }
    Ok(())
}

fn raw(reader: Option<&str>, apdu: &str, select: Option<String>) -> Result<()> {
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());
    if let Some(spec) = select {
        let aid = hex_bytes(&spec)?;
        let mut cmd = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        cmd.extend_from_slice(&aid);
        cmd.push(0x00);
        let resp = card.transmit_full(&cmd)?;
        println!("select  -> {}", hex::encode(&resp).to_uppercase());
    }
    // several APDUs can be chained with commas, which is the only way to keep card state
    let mut last;
    for (index, part) in apdu.split(',').enumerate() {
        let bytes = hex_bytes(part)?;
        last = card.transmit_full(&bytes)?;
        let sw = if last.len() >= 2 {
            u16::from_be_bytes([last[last.len() - 2], last[last.len() - 1]])
        } else { 0 };
        println!("apdu {:<2} -> {:04X}  {}", index + 1, sw, hex::encode(&last).to_uppercase());
    }
    Ok(())
}

fn key_type_name(value: u8) -> &'static str {
    match value {
        0x80 => "AES",
        0x81 => "3DES (2-key)",
        0x82 => "3DES (3-key)",
        0x83 => "DES",
        0x84 => "RSA public exponent/modulus",
        0x85 => "RSA private exponent/modulus",
        0x88 => "AES (SM4?)",
        _ => "unknown",
    }
}

/// Decode the C0 key information entries: key version, key index, type, length.
fn decode_key_info(data: &[u8]) -> Vec<(u8, u8, u8, u8)> {
    let mut out = Vec::new();
    // the template is wrapped in E0; enter it before reading the C0 entries
    let data = if data.len() > 2 && data[0] == 0xE0 {
        let len = data[1] as usize;
        if data.len() >= 2 + len { &data[2..2 + len] } else { &data[2..] }
    } else {
        data
    };
    let mut at = 0usize;
    while at + 2 <= data.len() {
        let tag = data[at];
        let len = data[at + 1] as usize;
        if at + 2 + len > data.len() {
            break;
        }
        let value = &data[at + 2..at + 2 + len];
        if tag == 0xC0 && value.len() >= 4 {
            out.push((value[0], value[1], value[2], value[3]));
        }
        at += 2 + len;
    }
    out
}

fn keys(reader: Option<&str>, sd: Option<String>) -> Result<()> {
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());
    let aid = match sd {
        Some(spec) => hex_bytes(&spec)?,
        None => hex::decode("A000000003000000").expect("constant"),
    };
    let mut select = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
    select.extend_from_slice(&aid);
    select.push(0x00);
    let resp = card.transmit_full(&select)?;
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    if sw != 0x9000 {
        anyhow::bail!("selecting {} failed: {sw:04X}", hex::encode(&aid).to_uppercase());
    }

    let raw = card.transmit_full(&[0x80u8, 0xCA, 0x00, 0xE0, 0x20])?;
    let sw = u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
    if sw != 0x9000 {
        anyhow::bail!("GET DATA 00E0 failed: {sw:04X}. The card will not disclose its key sets");
    }
    let entries = decode_key_info(&raw[..raw.len() - 2]);
    if entries.is_empty() {
        println!("no key information returned");
        return Ok(());
    }
    println!("{:<4} {:<5} {:<8} {:<7} {}", "KVN", "INDEX", "TYPE", "BYTES", "MEANS");
    for (kvn, index, kind, len) in entries {
        println!("{:<4} {:<5} 0x{:02X}     {:<7} {}", kvn, index, kind, len, key_type_name(kind));
    }
    println!();
    println!("These are the key sets the card holds. Without the matching static keys the channel");
    println!("cannot be opened, and no loader can proceed; the values above are what you ask the");
    println!("card issuer for.");
    Ok(())
}

fn check(reader: Option<&str>, sd: Option<String>, keys: &Option<String>,
         keys_file: &Option<String>, scp: &Option<String>) -> Result<()> {
    use tuddenham_tca_loader::session::Session;

    let static_keys = resolve_keys(keys, keys_file, scp)?;
    let mut card = PcscTransport::open(reader)?;
    println!("reader: {}", card.describe());
    let aid = match sd {
        Some(spec) => hex_bytes(&spec)?,
        None => hex::decode("A000000003000000").expect("constant"),
    };
    let mut select = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
    select.extend_from_slice(&aid);
    select.push(0x00);
    let resp = card.transmit_full(&select)?;
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    if sw != 0x9000 {
        anyhow::bail!("selecting {} failed: {sw:04X}", hex::encode(&aid).to_uppercase());
    }
    println!("domain:  {}", hex::encode(&aid).to_uppercase());

    let verdict = Session::check(&mut card, &static_keys)
        .context("the card would not even issue a challenge")?;
    println!("SCP:     SCP{:02X}, {}-byte {}", verdict.challenge.scp,
             if verdict.challenge.scp == 0x02 { 8 } else { verdict.challenge.mode },
             if verdict.challenge.scp == 0x02 { "MAC" } else { "cryptograms" });
    println!("card:    challenge {} cryptogram {}",
             hex::encode(&verdict.challenge.card_challenge).to_uppercase(),
             hex::encode(&verdict.challenge.card_cryptogram).to_uppercase());
    if verdict.matches {
        println!("keys:    MATCH. These keys open this card.");
        println!();
        println!("Nothing was authenticated yet, so no retry counter moved. Run `auth`, `load` or");
        println!("`delete` with the same keys whenever you are ready.");
    } else {
        println!("keys:    do not match. The card computed a different cryptogram, so these are not\n");
        println!("         its static keys. Nothing was sent that spends an authentication attempt.");
        println!();
        println!("Ask the issuer for the key set listed by `keys --sd {}`.",
                 hex::encode(&aid).to_uppercase());
    }
    Ok(())
}

fn audit(reader: Option<&str>, sd: Option<String>, keys: &Option<String>,
         keys_file: &Option<String>, scp: &Option<String>) -> Result<()> {
    let (mut card, mut session) = open_session(reader, sd, keys, keys_file, scp)?;
    let resp = session.execute(&mut card, 0x80, 0xF2, 0x40, 0x00, &[0x4F, 0x00], Some(0x00))?;
    if !resp.is_ok() {
        anyhow::bail!("GET STATUS over the channel failed: {} ({:04X})",
                      resp.describe(), resp.status());
    }
    let entries = tuddenham_tca_loader::gp::parse_get_status(&resp.data);
    println!();
    println!("{:<34} {:<14} {}", "AID", "STATE", "PRIVILEGES");
    let mut counts = std::collections::BTreeMap::new();
    for entry in entries.iter() {
        println!("{:<34} {:<14} {:02X?}",
                 entry.aid_hex(), entry.life_cycle_short(), entry.privileges);
        *counts.entry(entry.life_cycle_short().to_string()).or_insert(0) += 1;
    }
    println!();
    println!("{} entries", entries.len());
    for (state, count) in counts {
        println!("  {:<14} {count}", state);
    }
    Ok(())
}

fn dump(reader: Option<&str>, out: &str) -> Result<()> {
    use std::io::Write;

    let mut card = PcscTransport::open(reader)?;
    let mut report = String::new();
    report.push_str(&format!("reader: {}\n", card.describe()));
    report.push_str(&format!("ATR:    {}\n",
        card.atr_hex().unwrap_or_else(|e| format!("unavailable ({e})"))));

    fn sw_of(raw: &[u8]) -> u16 {
        if raw.len() >= 2 {
            u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]])
        } else { 0 }
    }
    fn select(card: &mut PcscTransport, aid: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut apdu = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        apdu.extend_from_slice(aid);
        apdu.push(0x00);
        let raw = card.transmit_full(&apdu)?;
        Ok((raw[..raw.len().saturating_sub(2)].to_vec(), sw_of(&raw)))
    }

    // EF_DIR: the applications the card actually holds. Files are selected by FID, not by AID.
    let _ = card.transmit_full(&[0x00u8, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]);
    let dir_raw = card.transmit_full(&[0x00u8, 0xA4, 0x00, 0x0C, 0x02, 0x2F, 0x00])?;
    let sw = sw_of(&dir_raw);
    report.push_str("\napplications (EF_DIR):\n");
    if sw != 0x9000 {
        report.push_str(&format!("  not readable ({sw:04X})\n"));
    } else {
        for record in 1u8..=20 {
            let raw = card.transmit_full(&[0x00u8, 0xB2, record, 0x04, 0x26])?;
            if sw_of(&raw) != 0x9000 {
                break;
            }
            let body = &raw[..raw.len() - 2];
            let mut aid = String::from("-");
            let mut label = String::from("-");
            let mut at = 0usize;
            while at + 2 <= body.len() {
                let tag = body[at];
                let len = body[at + 1] as usize;
                if at + 2 + len > body.len() {
                    break;
                }
                let value = &body[at + 2..at + 2 + len];
                if tag == 0x61 {
                    let mut inner = 0usize;
                    while inner + 2 <= value.len() {
                        let t2 = value[inner];
                        let l2 = value[inner + 1] as usize;
                        if inner + 2 + l2 > value.len() {
                            break;
                        }
                        let v2 = &value[inner + 2..inner + 2 + l2];
                        match t2 {
                            0x4F => aid = hex::encode(v2).to_uppercase(),
                            0x50 => label = String::from_utf8_lossy(v2).trim().to_string(),
                            _ => {}
                        }
                        inner += 2 + l2;
                    }
                }
                at += 2 + len;
            }
            report.push_str(&format!("  {aid}  {label}\n"));
        }
    }

    // the card manager, if there is one at any of the usual AIDs
    report.push_str("\ncard manager:\n");
    let mut found = false;
    for (name, aid_hex) in [
        ("GP issuer domain", "A000000003000000"),
        ("GP card manager", "A000000151000000"),
        ("GSMA ISD-R", "A0000005591010FFFFFF8901000000"),
    ] {
        let bytes = hex::decode(aid_hex).expect("constant");
        let (fci, sw) = select(&mut card, &bytes)?;
        report.push_str(&format!("  {name:<22} {aid_hex}  {sw:04X}\n"));
        if sw == 0x9000 {
            found = true;
            report.push_str(&format!("    FCI: {}\n", hex::encode(&fci).to_uppercase()));
            let raw = card.transmit_full(&[0x80u8, 0xCA, 0x00, 0xE0, 0x20])?;
            report.push_str(&format!("    keys: {:04X} {}\n",
                sw_of(&raw), hex::encode(&raw[..raw.len().saturating_sub(2)]).to_uppercase()));
        }
    }
    if !found {
        report.push_str("  none answered at the standard AIDs\n");
    }

    let mut file = std::fs::File::create(out)
        .with_context(|| format!("writing {out}"))?;
    file.write_all(report.as_bytes())?;
    println!("wrote {out} ({} bytes)", report.len());
    Ok(())
}
