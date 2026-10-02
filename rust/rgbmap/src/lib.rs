//! Recompute what an RGBMap index says, without asking it to be believed.
//!
//! The rules are published at <https://rgbmap.org/docs>. This crate implements them; it holds
//! no client and reaches no network, so a caller decides where bytes come from.
//!
//! 🚨 There is no `is_valid`, no `is_verified` and no `is_trusted` here, and there will not be.
//! Every status stands on its own and merging them into a verdict is precisely what RGBMap
//! does not do: <https://rgbmap.org/docs/what-rgbmap-does-not-state>.

pub mod canonical;
pub mod declaration;
pub mod ledger;

pub use canonical::{canonicalize, CanonicalError};
pub use declaration::{check_signature, message_for, signing_digest, verify_bip322};
pub use ledger::{anchor_commitment, entry_hash, legs_balance, public_commitment, sha256_hex, GENESIS};
