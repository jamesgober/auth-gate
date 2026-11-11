//! The locks the in-memory stores use: the standard library's, or loom's
//! when the crate is built for model checking (`RUSTFLAGS="--cfg loom"`).

#[cfg(loom)]
pub(crate) use loom::sync::{Mutex, RwLock};
#[cfg(not(loom))]
pub(crate) use std::sync::{Mutex, RwLock};
