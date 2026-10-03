//! vulnwatch: inventory-based vulnerability digest.
//!
//! Collectors (`vulnwatch collect`, every host) report what is installed; the analyzer
//! (`vulnwatch run`, anubis) matches that against the Debian/Arch trackers, OSV and Trivy,
//! weighs it with CISA KEV, EPSS and exposure, and reports only what is new or still open.

pub mod analyze;
pub mod collect;
pub mod config;
pub mod feeds;
pub mod inventory;
pub mod model;
pub mod notify;
pub mod report;
pub mod state;
pub mod summary;
pub mod version;
