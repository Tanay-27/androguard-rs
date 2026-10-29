use alloc::string::String;
use core::fmt;

use std::error::Error;

// MODIFIED from upstream androguard/dex-bytecode; see VENDORED.md.
#[derive(Clone)]
pub struct DexError {
    /// androguard 4.1.3's message for the inner InvalidInstruction.
    error: String,
    /// Byte offset the linear sweep stopped at (set by `decode_all*`).
    pub offset: Option<usize>,
}

impl DexError {
    /// Invalid instruction or truncated buffer.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self { error: msg.into(), offset: None }
    }

    /// Invalid instruction with dynamic message (allocates).
    pub fn invalid_owned(msg: String) -> Self {
        Self { error: msg, offset: None }
    }

    /// androguard's message for the inner InvalidInstruction.
    pub fn message(&self) -> &str {
        &self.error
    }
}

impl core::fmt::Debug for DexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DexError")
            .field("error", &self.error)
            .finish()
    }
}

impl Error for DexError {}

impl fmt::Display for DexError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}
