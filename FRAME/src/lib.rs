//! FRAME daemon: application services, durable storage, Git transport and local API.
pub mod api;
pub mod archive;
mod browser_access;
pub mod daemon;
pub mod git;
pub mod identity;
pub mod lifecycle;
pub mod managed;
pub mod peer;
pub mod restore;
mod server;
pub mod snapshot;
pub mod ssh;
pub mod ssh_keys;
mod ssh_service;
pub mod store;
pub mod web_host;
