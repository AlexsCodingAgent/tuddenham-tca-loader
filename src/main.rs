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
    /// List security domains and applications with life cycle and privileges.
    Status {
        /// Only issuer security domains, not every application.
        #[arg(long)]
        isd_only: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Readers => list_readers(),
        Command::Info => info(cli.reader.as_deref()),
        Command::Status { isd_only } => status(cli.reader.as_deref(), isd_only),
    }
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
