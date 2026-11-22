//! tuddenham-tca-loader: an open reimplementation of a TCA-style application loader.
//!
//! The commercial TCALoader manages Java Card applications on a UICC or eUICC: compile an
//! applet, load it through a security domain, install it, and audit what the card holds.
//! This crate is the same job done in the open, in Rust, in stages:
//!
//! - `tlv` and `apdu` are the wire formats, complete and tested
//! - `card` is the transport: PC/SC today, CAT-TP and SIM-over-IP later
//! - `gp` is the GlobalPlatform read path: select the card manager, list domains and
//!   applications, read CPLC and card recognition data
//! - `scp03` and `session` are the secure channel: challenge, key derivation, cryptogram
//!   check, and MAC-wrapped commands
//! - loading, installation and deletion come next, which is what makes this a loader rather
//!   than an inspector
//!
//! Authentication opens the channel; it does not yet write anything to the card.

pub mod apdu;
pub mod cap;
pub mod card;
pub mod commands;
pub mod gp;
pub mod load;
pub mod scp02;
pub mod scp03;
pub mod session;
pub mod tlv;

pub use card::{PcscTransport, Transport};
pub use gp::{select_isd, AppEntry};
