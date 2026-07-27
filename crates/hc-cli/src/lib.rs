//! Library surface for `hc-cli`.
//!
//! Exists so integration tests (and, eventually, a hosted API handler) can
//! call command implementations directly rather than shelling out to the
//! `tinyzkp-engine` binary. `main.rs` keeps its own copy of these modules;
//! see the comment there for why.
pub mod commands;
pub mod protocol;
