//! Per-object capability matching. Pure: takes a parsed ELF and a database,
//! touches no files.

use crate::capdb::CapDb;
use crate::elf::ElfFile;
use std::collections::BTreeSet;
use std::fmt;

/// Imports that let an object resolve symbols by name at run time, which is
/// what makes a symbol-name string in `.rodata` meaningful.
pub const DYNAMIC_LOADERS: &[&str] = &["dlopen", "dlmopen", "dlsym", "dlvsym"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// The object has an undefined dynamic symbol from the database.
    Direct,
    /// Inferred from read-only strings: a symbol name next to a dlopen/dlsym
    /// import, or a D-Bus interface name.
    Indirect,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Direct => "direct",
            Confidence::Indirect => "indirect",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Evidence {
    pub capability: String,
    pub symbol: String,
    /// GNU version of the import, e.g. `XCB_1.0`, when the object records one.
    pub version: Option<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectAnalysis {
    pub evidence: Vec<Evidence>,
    pub imports_dynamic_loader: bool,
    /// Library names found in read-only strings of an object that can dlopen.
    pub dlopen_candidates: Vec<String>,
}

pub fn analyze(elf: &ElfFile, db: &CapDb) -> ObjectAnalysis {
    let mut evidence = BTreeSet::new();
    let mut direct_symbols = BTreeSet::new();
    let mut imports_dynamic_loader = false;

    for sym in elf.imports() {
        if DYNAMIC_LOADERS.contains(&sym.name.as_str()) {
            imports_dynamic_loader = true;
        }
        if let Some(cap) = db.for_symbol(&sym.name) {
            direct_symbols.insert(sym.name.clone());
            evidence.insert(Evidence {
                capability: cap.id.clone(),
                symbol: sym.name.clone(),
                version: sym.version.as_ref().map(|v| v.name.clone()),
                confidence: Confidence::Direct,
            });
        }
    }

    let mut dlopen_candidates = Vec::new();
    for s in &elf.rodata_strings {
        if let Some(cap) = db.for_string(s) {
            evidence.insert(Evidence {
                capability: cap.id.clone(),
                symbol: s.clone(),
                version: None,
                confidence: Confidence::Indirect,
            });
        }
        if !imports_dynamic_loader {
            continue;
        }
        if let Some(cap) = db.for_symbol(s) {
            // A direct import of the same symbol already says more.
            if !direct_symbols.contains(s) {
                evidence.insert(Evidence {
                    capability: cap.id.clone(),
                    symbol: s.clone(),
                    version: None,
                    confidence: Confidence::Indirect,
                });
            }
        }
        if looks_like_library_name(s) {
            dlopen_candidates.push(s.clone());
        }
    }

    ObjectAnalysis {
        evidence: evidence.into_iter().collect(),
        imports_dynamic_loader,
        dlopen_candidates,
    }
}

fn looks_like_library_name(s: &str) -> bool {
    let base = s.rsplit('/').next().unwrap_or(s);
    base.starts_with("lib")
        && (base.ends_with(".so") || base.contains(".so."))
        && !base.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::looks_like_library_name;

    #[test]
    fn library_name_heuristic() {
        assert!(looks_like_library_name("libX11.so.6"));
        assert!(looks_like_library_name("libXtst.so"));
        assert!(looks_like_library_name("/usr/lib/libpipewire-0.3.so.0"));
        assert!(!looks_like_library_name("library"));
        assert!(!looks_like_library_name("failed to load libX11.so.6"));
        assert!(!looks_like_library_name("libfoo.sort"));
    }
}
