//! Shared error primitives for the `hc-stark` workspace.
//!
//! Every crate in the workspace should depend on this module (re-exported
//! from `hc-core`) rather than inventing its own bespoke error enumerations.
//! Doing so gives us predictable error messages, simplifies logging /
//! observability, and makes it trivial to bubble failures across crate
//! boundaries without losing context.

use std::{borrow::Cow, io};

use thiserror::Error;

/// Convenient alias for results that use [`HcError`] as the failure type.
pub type HcResult<T> = Result<T, HcError>;

/// Unified error type for the entire workspace.
#[derive(Debug, Error)]
pub enum HcError {
    /// The caller supplied an argument that violated documented preconditions.
    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },

    /// The system reached a state that violates algebraic assumptions.
    #[error("math error: {detail}")]
    Math { detail: String },

    /// Serialization or deserialization failed.
    #[error("serialization error: {detail}")]
    Serialization { detail: String },

    /// A requested feature has not been implemented yet.
    #[error("unimplemented: {feature}")]
    Unimplemented { feature: String },

    /// Wrapper around standard I/O errors so they can flow through the stack.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Catch-all error message for situations that do not fit the categories
    /// above but still need to bubble up to the caller.
    #[error("{message}")]
    Message { message: String },
}

impl HcError {
    /// Creates a terse error from a static message.
    pub fn message(msg: impl Into<String>) -> Self {
        Self::Message {
            message: msg.into(),
        }
    }

    /// Creates an [`HcError::InvalidArgument`] from the supplied detail.
    pub fn invalid_argument(detail: impl Into<String>) -> Self {
        Self::InvalidArgument {
            detail: detail.into(),
        }
    }

    /// Creates an [`HcError::Math`] variant.
    pub fn math(detail: impl Into<String>) -> Self {
        Self::Math {
            detail: detail.into(),
        }
    }

    /// Creates an [`HcError::Serialization`] variant.
    pub fn serialization(detail: impl Into<String>) -> Self {
        Self::Serialization {
            detail: detail.into(),
        }
    }

    /// Creates an [`HcError::Unimplemented`] variant.
    pub fn unimplemented(feature: impl Into<String>) -> Self {
        Self::Unimplemented {
            feature: feature.into(),
        }
    }
}

/// Extension helpers for `Result` so that we can annotate errors with context
/// in a fluent manner.
pub trait ResultExt<T> {
    /// Adds contextual information to any error produced by the receiver.
    fn context(self, context: impl Into<Cow<'static, str>>) -> HcResult<T>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Into<HcError>,
{
    fn context(self, context: impl Into<Cow<'static, str>>) -> HcResult<T> {
        self.map_err(|error| {
            let ctx = context.into();
            let mut message = String::with_capacity(128);
            message.push_str(ctx.as_ref());
            message.push_str(": ");
            message.push_str(&error.into().to_string());
            HcError::message(message)
        })
    }
}

/// Helper macro similar to `anyhow::ensure` but using [`HcError`].
#[macro_export]
macro_rules! hc_ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err);
        }
    };
}
