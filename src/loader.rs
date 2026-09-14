//! Dependency resolution inside a bundle directory, following the search order
//! of glibc's ld.so for `DT_NEEDED` names:
//!
//! 1. If the requesting object has no `DT_RUNPATH`: the `DT_RPATH` of the
//!    requesting object, then of the object that loaded it, and so on up to the
//!    executable. Objects that have a `DT_RUNPATH` contribute no `DT_RPATH`.
//! 2. `LD_LIBRARY_PATH` (not modelled: it belongs to the environment, not the files).
//! 3. The requesting object's own `DT_RUNPATH`. It is never inherited.
//! 4. ld.so.cache and the default directories. Anything that gets this far is
//!    a system library and is left unresolved.
//!
//! A name that matches the `DT_SONAME` of, or a `DT_NEEDED` name that already
//! found, an object loaded earlier is reused without searching, which is also
//! what makes dependency cycles terminate.

use crate::elf::{Class, ElfFile, Endian};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Debug)]
pub struct Object {
    /// Canonical path on disk.
    pub path: PathBuf,
    /// Path relative to the bundle root, with `/` separators.
    pub rel: String,
    pub elf: ElfFile,
}

#[derive(Debug, Clone)]
pub struct NeededLink {
    pub name: String,
    /// Index into the load list, or `None` when ld.so would go to the system.
    pub resolved: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct LoadedObject {
    pub object: Rc<Object>,
    /// Index of the object whose `DT_NEEDED` caused this one to load.
    pub loader: Option<usize>,
    pub needed: Vec<NeededLink>,
    /// Directory `$ORIGIN` expands to: where the object was found, before
    /// symlinks are resolved, as ld.so sees it.
    origin: PathBuf,
    names: Vec<String>,
}

enum Cached {
    Elf(Rc<Object>),
    Skipped,
}

pub struct Bundle {
    root: PathBuf,
    cache: HashMap<PathBuf, Cached>,
    errors: BTreeMap<String, String>,
}

type Target = (Class, Endian, u16);

impl Bundle {
    pub fn new(root: &Path) -> io::Result<Bundle> {
        Ok(Bundle {
            root: fs::canonicalize(root)?,
            cache: HashMap::new(),
            errors: BTreeMap::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Files that looked like ELF (or could not be read) but failed to load,
    /// keyed by path relative to the root.
    pub fn errors(&self) -> &BTreeMap<String, String> {
        &self.errors
    }

    pub fn record_error(&mut self, rel: String, message: String) {
        self.errors.insert(rel, message);
    }

    pub fn relative(&self, canonical: &Path) -> Option<String> {
        let rest = canonical.strip_prefix(&self.root).ok()?;
        let parts: Vec<String> = rest
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        Some(parts.join("/"))
    }

    /// Loads an ELF file inside the root. Returns `None` for anything outside
    /// the root, non-ELF files, and files that fail to parse (recorded in
    /// [`Bundle::errors`]).
    pub fn open(&mut self, path: &Path) -> Option<Rc<Object>> {
        let canonical = fs::canonicalize(path).ok()?;
        let rel = self.relative(&canonical)?;
        if let Some(cached) = self.cache.get(&canonical) {
            return match cached {
                Cached::Elf(object) => Some(Rc::clone(object)),
                Cached::Skipped => None,
            };
        }
        let entry = match read_elf(&canonical) {
            Ok(Some(elf)) => Cached::Elf(Rc::new(Object {
                path: canonical.clone(),
                rel,
                elf,
            })),
            Ok(None) => Cached::Skipped,
            Err(message) => {
                self.errors.insert(rel, message);
                Cached::Skipped
            }
        };
        let result = match &entry {
            Cached::Elf(object) => Some(Rc::clone(object)),
            Cached::Skipped => None,
        };
        self.cache.insert(canonical, entry);
        result
    }

    /// Emulates loading `entry` and its `DT_NEEDED` closure breadth-first, the
    /// order ld.so maps dependencies in. Index 0 is `entry`.
    pub fn simulate(&mut self, entry: Rc<Object>) -> Vec<LoadedObject> {
        let origin = entry
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let names = entry.elf.soname.iter().cloned().collect();
        let mut loaded = vec![LoadedObject {
            object: entry,
            loader: None,
            needed: Vec::new(),
            origin,
            names,
        }];
        let mut i = 0;
        while i < loaded.len() {
            let object = Rc::clone(&loaded[i].object);
            let mut links = Vec::with_capacity(object.elf.needed.len());
            for name in &object.elf.needed {
                let resolved = match loaded.iter().position(|l| l.names.contains(name)) {
                    Some(j) => Some(j),
                    None => self.search(&loaded, i, name).map(|(found, origin)| {
                        match loaded.iter().position(|l| l.object.path == found.path) {
                            Some(j) => {
                                loaded[j].names.push(name.clone());
                                j
                            }
                            None => {
                                let mut names: Vec<String> =
                                    found.elf.soname.iter().cloned().collect();
                                names.push(name.clone());
                                loaded.push(LoadedObject {
                                    object: found,
                                    loader: Some(i),
                                    needed: Vec::new(),
                                    origin,
                                    names,
                                });
                                loaded.len() - 1
                            }
                        }
                    }),
                };
                links.push(NeededLink {
                    name: name.clone(),
                    resolved,
                });
            }
            loaded[i].needed = links;
            i += 1;
        }
        loaded
    }

    fn search(
        &mut self,
        loaded: &[LoadedObject],
        requester: usize,
        name: &str,
    ) -> Option<(Rc<Object>, PathBuf)> {
        let req = &loaded[requester];
        let target = (
            req.object.elf.class,
            req.object.elf.endian,
            req.object.elf.machine,
        );

        if name.contains('/') {
            // ld.so opens such names directly; a relative one is relative to the
            // working directory at run time, which the bundle root stands in for.
            let path = if Path::new(name).is_absolute() {
                PathBuf::from(name)
            } else {
                self.root.join(name)
            };
            return self.candidate(&path, target);
        }

        let mut dirs = Vec::new();
        if req.object.elf.runpath.is_none() {
            let mut cursor = Some(requester);
            while let Some(k) = cursor {
                let l = &loaded[k];
                if l.object.elf.runpath.is_none() {
                    if let Some(rpath) = &l.object.elf.rpath {
                        dirs.extend(expand_search_path(rpath, &l.origin));
                    }
                }
                cursor = l.loader;
            }
        }
        if let Some(runpath) = &req.object.elf.runpath {
            dirs.extend(expand_search_path(runpath, &req.origin));
        }
        dirs.iter()
            .find_map(|dir| self.candidate(&dir.join(name), target))
    }

    fn candidate(&mut self, path: &Path, target: Target) -> Option<(Rc<Object>, PathBuf)> {
        let object = self.open(path)?;
        // ld.so skips files built for another class or machine and keeps searching.
        if (object.elf.class, object.elf.endian, object.elf.machine) != target {
            return None;
        }
        let origin = path.parent()?.to_path_buf();
        Some((object, origin))
    }
}

fn read_elf(path: &Path) -> Result<Option<ElfFile>, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Ok(None);
    }
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut magic = [0u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) if &magic == b"\x7fELF" => {}
        Ok(()) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let mut data = magic.to_vec();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;
    ElfFile::parse(&data).map(Some).map_err(|e| e.to_string())
}

/// Splits a colon-separated RPATH/RUNPATH and expands `$ORIGIN`. Entries that
/// stay relative or use `$LIB`/`$PLATFORM` depend on the run-time environment
/// and are dropped.
pub fn expand_search_path(list: &str, origin: &Path) -> Vec<PathBuf> {
    let Some(origin) = origin.to_str() else {
        return Vec::new();
    };
    list.split(':')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| expand_origin(entry, origin))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .collect()
}

pub fn expand_origin(entry: &str, origin: &str) -> Option<String> {
    let mut out = String::with_capacity(entry.len() + origin.len());
    let mut rest = entry;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix("{ORIGIN}") {
            out.push_str(origin);
            rest = tail;
        } else {
            // Bare $ORIGIN, but only when what follows cannot be part of a
            // longer variable name — $ORIGINAL is not an expansion.
            let tail = after
                .strip_prefix("ORIGIN")
                .filter(|t| !t.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))?;
            out.push_str(origin);
            rest = tail;
        }
    }
    out.push_str(rest);
    Some(out)
}

/// Regular files under `dir`, sorted. Symlinks are not followed, so link
/// farms (`libfoo.so -> libfoo.so.1.2`) are counted once and loops cannot
/// recurse; resolution still follows symlinks when a search path hits one.
pub fn walk(dir: &Path, errors: &mut Vec<(PathBuf, String)>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                errors.push((current, e.to_string()));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => stack.push(path),
                Ok(meta) if meta.is_file() => files.push(path),
                Ok(_) => {}
                Err(e) => errors.push((path, e.to_string())),
            }
        }
    }
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_expansion() {
        assert_eq!(
            expand_origin("$ORIGIN/../lib", "/b/bin").unwrap(),
            "/b/bin/../lib"
        );
        assert_eq!(expand_origin("${ORIGIN}/x:y", "/o").unwrap(), "/o/x:y");
        assert_eq!(expand_origin("/abs", "/o").unwrap(), "/abs");
        assert_eq!(expand_origin("$ORIGIN", "/o").unwrap(), "/o");
        assert!(expand_origin("$ORIGINAL/lib", "/o").is_none());
        assert!(expand_origin("$LIB/x", "/o").is_none());
        assert!(expand_origin("/x/$PLATFORM", "/o").is_none());
    }

    #[test]
    fn search_path_drops_empty_relative_and_unknown_entries() {
        let dirs = expand_search_path("::$ORIGIN/a:rel/dir:$LIB:/abs", Path::new("/r/bin"));
        assert_eq!(dirs, [PathBuf::from("/r/bin/a"), PathBuf::from("/abs")]);
    }
}
