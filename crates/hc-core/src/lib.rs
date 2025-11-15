#![forbid(unsafe_code)]

//! Core math primitives, shared error types, and utilities for the hc-STARK
//! workspace.

pub mod bytes;
pub mod domain;
pub mod error;
pub mod fft;
pub mod field;
pub mod poly;
pub mod random;
pub mod utils;

pub use error::{HcError, HcResult, ResultExt};
