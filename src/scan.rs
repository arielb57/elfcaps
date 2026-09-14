//! Builds a [`Report`] for a directory or a single binary.

use crate::analysis::{analyze, Confidence};
use crate::capdb::CapDb;
use crate::elf::{ElfError, ElfFile};
use crate::loader::{walk, Bundle, LoadedObject, Object};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub root: String,
    pub objects: Vec<ObjectReport>,
    pub findings: Vec<Finding>,
    pub errors: Vec<FileError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReport {
    pub path: String,
    pub executable: bool,
    pub format: String,
    pub machine: u16,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub needed: Vec<NeededReport>,
    pub imports_dynamic_loader: bool,
    pub dlopen_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeededReport {
    pub name: String,
    /// Bundle-relative path of the object ld.so would load, or `None` when the
    /// search leaves the bundle (a system library, or a missing one).
    pub resolved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub capability: String,
    pub title: String,
    /// The bundled object that imports the symbol (or holds the string).
    pub object: String,
    pub symbol: String,
    pub version: Option<String>,
    pub confidence: Confidence,
    /// Load chains that bring `object` in, each starting at the object ld.so
    /// was started on. Executables are simulated first, so chains from an
    /// executable come before chains from libraries nothing links to.
    pub reached_via: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    pub path: String,
    pub message: String,
}

#[derive(Debug)]
pub enum ScanError {
    Io { path: PathBuf, source: io::Error },
    OutsideRoot { path: PathBuf, root: PathBuf },
    NotElf(PathBuf),
    Parse { path: PathBuf, source: ElfError },
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            ScanError::OutsideRoot { path, root } => {
                write!(
                    f,
                    "{} is not inside root {}",
                    path.display(),
                    root.display()
                )
            }
            ScanError::NotElf(path) => write!(f, "{}: not an ELF file", path.display()),
            ScanError::Parse { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ScanError {}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> ScanError + '_ {
    move |source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Scans `target`, a directory tree or one ELF file. Dependencies are
/// resolved inside `root`, which defaults to the directory itself or to the
/// file's parent directory.
pub fn scan(target: &Path, root: Option<&Path>, db: &CapDb) -> Result<Report, ScanError> {
    let meta = fs::metadata(target).map_err(io_error(target))?;
    let is_dir = meta.is_dir();
    let root_dir = match root {
        Some(r) => r.to_path_buf(),
        None if is_dir => target.to_path_buf(),
        None => match target.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        },
    };
    let mut bundle = Bundle::new(&root_dir).map_err(io_error(&root_dir))?;
    let canonical_target = fs::canonicalize(target).map_err(io_error(target))?;
    if !canonical_target.starts_with(bundle.root()) {
        return Err(ScanError::OutsideRoot {
            path: target.to_path_buf(),
            root: bundle.root().to_path_buf(),
        });
    }

    let mut objects: Vec<Rc<Object>> = Vec::new();
    if is_dir {
        let mut walk_errors = Vec::new();
        for file in walk(&canonical_target, &mut walk_errors) {
            if let Some(object) = bundle.open(&file) {
                objects.push(object);
            }
        }
        for (path, message) in walk_errors {
            let rel = bundle
                .relative(&path)
                .unwrap_or_else(|| path.display().to_string());
            bundle.record_error(rel, message);
        }
    } else {
        let data = fs::read(target).map_err(io_error(target))?;
        match ElfFile::parse(&data) {
            Err(ElfError::NotElf) => return Err(ScanError::NotElf(target.to_path_buf())),
            Err(source) => {
                return Err(ScanError::Parse {
                    path: target.to_path_buf(),
                    source,
                })
            }
            Ok(_) => objects.extend(bundle.open(&canonical_target)),
        }
    }

    let mut state = State::default();
    let (executables, libraries): (Vec<_>, Vec<_>) =
        objects.into_iter().partition(|o| o.elf.is_executable());
    for entry in executables {
        let loaded = bundle.simulate(entry);
        state.record(&loaded);
    }
    // Libraries no executable links to (plugins, helpers loaded with dlopen)
    // are still part of the attack surface, so each becomes its own root.
    for library in libraries {
        if !state.reached.contains_key(&library.rel) {
            let loaded = bundle.simulate(library);
            state.record(&loaded);
        }
    }

    let mut findings = Vec::new();
    let mut object_reports = Vec::new();
    for (rel, object) in &state.reached {
        let analysis = analyze(&object.elf, db);
        let chains = state.chains.get(rel).cloned().unwrap_or_default();
        for ev in analysis.evidence {
            findings.push(Finding {
                title: db
                    .get(&ev.capability)
                    .map(|c| c.title.clone())
                    .unwrap_or_default(),
                capability: ev.capability,
                object: rel.clone(),
                symbol: ev.symbol,
                version: ev.version,
                confidence: ev.confidence,
                reached_via: chains.clone(),
            });
        }
        object_reports.push(ObjectReport {
            path: rel.clone(),
            executable: object.elf.is_executable(),
            format: object.elf.class_name().to_string(),
            machine: object.elf.machine,
            soname: object.elf.soname.clone(),
            rpath: object.elf.rpath.clone(),
            runpath: object.elf.runpath.clone(),
            needed: state.needed.get(rel).cloned().unwrap_or_default(),
            imports_dynamic_loader: analysis.imports_dynamic_loader,
            dlopen_candidates: analysis.dlopen_candidates,
        });
    }
    findings.sort_by(|a, b| {
        (db.rank(&a.capability), &a.object, a.confidence, &a.symbol).cmp(&(
            db.rank(&b.capability),
            &b.object,
            b.confidence,
            &b.symbol,
        ))
    });

    Ok(Report {
        root: root_dir.display().to_string(),
        objects: object_reports,
        findings,
        errors: bundle
            .errors()
            .iter()
            .map(|(path, message)| FileError {
                path: path.clone(),
                message: message.clone(),
            })
            .collect(),
    })
}

#[derive(Default)]
struct State {
    reached: BTreeMap<String, Rc<Object>>,
    chains: HashMap<String, Vec<Vec<String>>>,
    needed: HashMap<String, Vec<NeededReport>>,
}

impl State {
    fn record(&mut self, loaded: &[LoadedObject]) {
        for (index, l) in loaded.iter().enumerate() {
            let rel = &l.object.rel;
            let mut chain = Vec::new();
            let mut cursor = Some(index);
            while let Some(k) = cursor {
                chain.push(loaded[k].object.rel.clone());
                cursor = loaded[k].loader;
            }
            chain.reverse();
            let chains = self.chains.entry(rel.clone()).or_default();
            if !chains.contains(&chain) {
                chains.push(chain);
            }
            // Resolution can differ per chain because RPATH is inherited; the
            // first simulation (an executable's, when there is one) is kept.
            self.needed.entry(rel.clone()).or_insert_with(|| {
                l.needed
                    .iter()
                    .map(|n| NeededReport {
                        name: n.name.clone(),
                        resolved: n.resolved.map(|j| loaded[j].object.rel.clone()),
                    })
                    .collect()
            });
            self.reached
                .entry(rel.clone())
                .or_insert_with(|| Rc::clone(&l.object));
        }
    }
}
