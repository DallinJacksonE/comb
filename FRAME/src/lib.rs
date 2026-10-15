//! FRAME daemon: application services, durable storage, Git transport and local API.
pub mod api;
pub mod archive;
pub mod daemon;
pub mod git;
pub mod identity;
pub mod lifecycle;
pub mod peer;
pub mod restore;
pub mod snapshot;
pub mod store;
