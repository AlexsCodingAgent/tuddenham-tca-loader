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
//! - loading, installation, deletion and SCP02/SCP03 authentication come next, which is
//!   what makes this a loader rather than an inspector
//!
//! Nothing here authenticates yet, so every command it sends is one a card answers before
//! a secure channel exists.

pub mod apdu;
pub mod card;
pub mod gp;
pub mod tlv;

pub use card::{PcscTransport, Transport};
pub use gp::{select_isd, AppEntry};
