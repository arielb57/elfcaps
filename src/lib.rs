//! Static audit of Linux binaries for privacy-sensitive X11, input and screen
//! capture APIs.
//!
//! The pipeline is: [`elf`] parses each object, [`loader`] resolves the
//! `DT_NEEDED` closure inside a bundle the way ld.so would, [`analysis`]
//! matches undefined imports and read-only strings against the [`capdb`]
//! database, and [`scan`] assembles a report that [`diff`] can compare and
//! [`output`] renders.

pub mod analysis;
pub mod capdb;
pub mod diff;
pub mod elf;
pub mod loader;
pub mod output;
pub mod scan;

pub use analysis::{analyze, Confidence, Evidence, ObjectAnalysis};
pub use capdb::{CapDb, Capability, DbError};
pub use diff::{diff, Diff};
pub use elf::{ElfError, ElfFile};
pub use scan::{scan, Finding, Report, ScanError};
