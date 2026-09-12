//! Project 1999 session engine and communication decoder.
//!
//! Use [`client::Client`] on a worker thread to connect and receive owned events.
//! Disable default features when embedding the library without the CLI.

pub mod assets;
pub mod chat;
pub mod client;
mod old_transport;
pub mod p99;
pub mod transport;
