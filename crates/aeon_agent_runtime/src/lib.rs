#![forbid(unsafe_code)]
//! AEON's governed host-side agent runtime.

pub mod action;
pub mod agent;
pub mod authority;
pub mod authority_kernel;
pub mod context;
pub mod digest;
pub mod error;
mod execution;
pub mod identity;
pub mod ids;
pub mod mission;
pub mod model;
pub mod protocol;
pub mod store;
pub mod supervisor;
pub mod tool_registry;

pub use action::*;
pub use agent::*;
pub use authority::*;
pub use authority_kernel::*;
pub use context::*;
pub use digest::*;
pub use error::{ErrorCode, RuntimeError};
pub use identity::*;
pub use ids::*;
pub use mission::*;
pub use model::*;
pub use protocol::*;
pub use store::*;
pub use supervisor::*;
pub use tool_registry::*;
