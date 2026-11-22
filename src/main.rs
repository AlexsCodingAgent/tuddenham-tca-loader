use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tuddenham_tca_loader::{card::PcscTransport, gp, Transport};

#[derive(Parser)]
#[command(name = "tca-loader", version, about = "Inspect and manage applications on a UICC or eUICC")]
struct Cli {
    /// Reader name fragment; the first reader with a card is used when omitted.
    #[arg(long, global = true)]
    reader: Option<String>,
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
        /// Static keys as enc:mac:dek in hex, 16 bytes each.
        #[arg(long)]
        keys: Option<String>,
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
        /// Static keys as enc:mac:dek in hex, 16 bytes each.
        #[arg(long)]
        keys: Option<String>,
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
        /// Static keys as enc:mac:dek in hex, 16 bytes each.
        #[arg(long)]
        keys: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Readers => list_readers(),
        Command::Info => info(cli.reader.as_deref()),
        Command::Auth { test_keys: _, keys, security_level, aid } =>
            auth(cli.reader.as_deref(), keys, security_level, aid),
        Command::Status { isd_only } => status(cli.reader.as_deref(), isd_only),
        Command::Cap { file, block_size } => cap_info(&file, block_size),
        Command::Load { file, sd, privileges, params, block_size, instance_aid, no_install,
                        not_selectable, keys } =>
            load_cap(cli.reader.as_deref(), &file, sd, &privileges, params, block_size,
                     instance_aid, no_install, not_selectable, keys),
        Command::Delete { aid, related, sd, keys } =>
            delete(cli.reader.as_deref(), &aid, related, sd, keys),
    }
}

fn parse_hex_u8(s: &str) -> std::result::Result<u8, String> {
    u8::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex_bytes(spec: &str) -> Result<Vec<u8>> {
    hex::decode(spec.replace(' ', "").trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("not hex: {e}"))
}

fn parse_keys(spec: &str) -> Result<tuddenham_tca_loader::scp03::Scp03Keys> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        anyhow::bail!("keys must be enc:mac:dek, 32 hex characters each");
    }
    let mut out = [[0u8; 16]; 3];
    for (i, part) in parts.iter().enumerate() {
        let bytes = hex::decode(part.replace(' ', ""))
            .map_err(|e| anyhow::anyhow!("key {i} is not hex: {e}"))?;
        if bytes.len() != 16 {
            anyhow::bail!("key {i} is {} bytes, expected 16", bytes.len());
        }
        out[i].copy_from_slice(&bytes);
    }
    Ok(tuddenham_tca_loader::scp03::Scp03Keys { enc: out[0], mac: out[1], dek: out[2] })
}

fn auth(reader: Option<&str>, keys: Option<String>, security_level: u8, aid: Option<String>) -> Result<()> {
    use tuddenham_tca_loader::session::Session;

    let static_keys = match keys {
        Some(spec) => parse_keys(&spec)?,
        None => tuddenham_tca_loader::scp03::TEST_KEYS,
    };
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
    keys: Option<String>,
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

    let (mut card, mut session) = open_session(reader, sd, keys)?;
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
    keys: Option<String>,
) -> Result<()> {
    let bytes = hex_bytes(aid)?;
    let (mut card, mut session) = open_session(reader, sd, keys)?;
    tuddenham_tca_loader::load::delete(&mut card, &mut session, &bytes, related)?;
    println!("deleted {}{}", aid.to_uppercase(), if related { " and its objects" } else { "" });
    Ok(())
}

fn open_session(
    reader: Option<&str>,
    sd: Option<String>,
    keys: Option<String>,
) -> Result<(PcscTransport, tuddenham_tca_loader::session::Session)> {
    use tuddenham_tca_loader::session::Session;

    let static_keys = match keys {
        Some(spec) => parse_keys(&spec)?,
        None => tuddenham_tca_loader::scp03::TEST_KEYS,
    };
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
    println!("secure channel: SCP03, {}-byte MAC, domain {}",
             session.mode, hex::encode(&session.sd_aid).to_uppercase());
    Ok((card, session))
}
