//! sezam-sync-core: the sync decisions of Sezam's desktop (Python), web page
//! (JS) and phone (Dart) as one pure state machine
//! (docs/SYNC_SINGLE_SOURCE.md point 4b).
//!
//! No I/O and no crypto. A client verifies signatures and hashes with its own
//! libsodium, keeps its storage and UI, and asks here for every decision that
//! the three clients used to make each in their own copy:
//!
//! - [`gate`]: may a pull reply be applied (410, a restored server, a commit
//!   the server handed out again), where the cursor goes, and whether the
//!   state at an unchanged checkpoint still matches;
//! - [`pull`]: what a pulled object does to a row with an unsent change
//!   (S1 identity: version number and content hash), and whether a batch is
//!   complete enough to apply;
//! - [`order`]: the order a pull batch is applied in and the order queued
//!   audit records are sent in;
//! - [`reapply`]: what a full resync does with the unsent changes it set
//!   aside;
//! - [`reseal`]: the send side after a re-key: the key an unsent write goes
//!   out under, when a replaced folder key may be opened, and whether a
//!   member revoked elsewhere still needs a re-key;
//! - [`teamlog`]: the signed team log's replay and every decision from it
//!   (who may write, hold or seal which key; refusals; forks), with the
//!   signatures checked by each client's libsodium in a second run.
//!
//! [`json::call`] is the one entry point the bindings (PyO3, wasm-bindgen,
//! flutter_rust_bridge) expose: an operation name and a JSON document in,
//! a JSON document out.

pub mod account;
pub mod audit;
pub mod authority;
pub mod formats;
pub mod gate;
pub mod json;
pub mod kdf;
pub mod messages;
pub mod order;
pub mod pull;
pub mod reapply;
pub mod rekey_archive;
pub mod reseal;
pub mod revive;
pub mod teamlog;
pub mod vouchers;

use serde::{Deserialize, Serialize};

/// The rules' version. A client names the one it was written for and refuses
/// another (review 782dde8: the rules changed under an unchanged 0.1.0, so a
/// stale installed core went unnoticed). Raise it with every change of an
/// operation's input, output or decision.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A server version as sync redesign S1 names it: its number and the hash
/// of its content. Two copies under one number are the same version only
/// when the hashes match too (tombstone GC lets a number be written again).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub version: i64,
    pub hash: String,
}
