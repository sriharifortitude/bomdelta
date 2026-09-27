//! Diff two CycloneDX SBOMs and grade each change by how much it needs a
//! reviewer. See the README for what is and isn't checked.

pub mod diff;
pub mod license;
pub mod purl;
pub mod report;
pub mod sbom;
pub mod version;
