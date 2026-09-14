//! The capability database: which symbols and strings mean what.
//!
//! The format is a small INI dialect documented at the top of
//! `caps/capabilities.db`. The default database is compiled into the binary so
//! the tool works with no files next to it; `--db` loads a replacement.

use std::collections::HashMap;
use std::fmt;

const BUILTIN: &str = include_str!("../caps/capabilities.db");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub title: String,
    pub rationale: String,
    pub symbols: Vec<String>,
    pub strings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CapDb {
    capabilities: Vec<Capability>,
    by_symbol: HashMap<String, usize>,
    by_string: HashMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    Syntax {
        line: usize,
        message: String,
    },
    /// A capability id, symbol or string appears twice.
    Duplicate {
        line: usize,
        name: String,
    },
    MissingField {
        capability: String,
        field: &'static str,
    },
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Syntax { line, message } => write!(f, "line {line}: {message}"),
            DbError::Duplicate { line, name } => write!(f, "line {line}: '{name}' is listed twice"),
            DbError::MissingField { capability, field } => {
                write!(f, "capability '{capability}' has no {field}")
            }
        }
    }
}

impl std::error::Error for DbError {}

impl CapDb {
    /// The database shipped in `caps/capabilities.db`. The test suite parses it,
    /// so a malformed edit fails `cargo test` rather than a user's scan.
    pub fn builtin() -> CapDb {
        match CapDb::parse(BUILTIN) {
            Ok(db) => db,
            Err(e) => panic!("built-in capability database is invalid: {e}"),
        }
    }

    pub fn parse(text: &str) -> Result<CapDb, DbError> {
        let mut capabilities: Vec<Capability> = Vec::new();
        let mut current_key: Option<String> = None;

        for (i, raw) in text.lines().enumerate() {
            let line_no = i + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if raw.starts_with([' ', '\t']) {
                let (Some(cap), Some(key)) = (capabilities.last_mut(), current_key.as_deref())
                else {
                    return Err(DbError::Syntax {
                        line: line_no,
                        message: "continuation line without a key".into(),
                    });
                };
                append_value(cap, key, trimmed, line_no)?;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('[') {
                let id = rest.strip_suffix(']').ok_or_else(|| DbError::Syntax {
                    line: line_no,
                    message: "section header must end with ']'".into(),
                })?;
                let id = id.trim();
                if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(DbError::Syntax {
                        line: line_no,
                        message: format!("invalid capability id '{id}'"),
                    });
                }
                if capabilities.iter().any(|c| c.id == id) {
                    return Err(DbError::Duplicate {
                        line: line_no,
                        name: id.to_string(),
                    });
                }
                capabilities.push(Capability {
                    id: id.to_string(),
                    title: String::new(),
                    rationale: String::new(),
                    symbols: Vec::new(),
                    strings: Vec::new(),
                });
                current_key = None;
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return Err(DbError::Syntax {
                    line: line_no,
                    message: "expected 'key = value'".into(),
                });
            };
            let key = key.trim();
            let Some(cap) = capabilities.last_mut() else {
                return Err(DbError::Syntax {
                    line: line_no,
                    message: "key outside of a [capability] section".into(),
                });
            };
            if !matches!(key, "title" | "rationale" | "symbols" | "strings") {
                return Err(DbError::Syntax {
                    line: line_no,
                    message: format!("unknown key '{key}'"),
                });
            }
            append_value(cap, key, value.trim(), line_no)?;
            current_key = Some(key.to_string());
        }

        let mut by_symbol = HashMap::new();
        let mut by_string = HashMap::new();
        for (index, cap) in capabilities.iter().enumerate() {
            if cap.title.is_empty() {
                return Err(missing(cap, "title"));
            }
            if cap.rationale.is_empty() {
                return Err(missing(cap, "rationale"));
            }
            if cap.symbols.is_empty() && cap.strings.is_empty() {
                return Err(missing(cap, "symbols or strings"));
            }
            for sym in &cap.symbols {
                if by_symbol.insert(sym.clone(), index).is_some() {
                    return Err(DbError::Duplicate {
                        line: line_of(text, sym),
                        name: sym.clone(),
                    });
                }
            }
            for s in &cap.strings {
                if by_string.insert(s.clone(), index).is_some() {
                    return Err(DbError::Duplicate {
                        line: line_of(text, s),
                        name: s.clone(),
                    });
                }
            }
        }
        Ok(CapDb {
            capabilities,
            by_symbol,
            by_string,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn get(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// Position in the database, used to order reports the way the file does.
    pub fn rank(&self, id: &str) -> usize {
        self.capabilities
            .iter()
            .position(|c| c.id == id)
            .unwrap_or(usize::MAX)
    }

    pub fn for_symbol(&self, name: &str) -> Option<&Capability> {
        self.by_symbol.get(name).map(|&i| &self.capabilities[i])
    }

    pub fn for_string(&self, s: &str) -> Option<&Capability> {
        self.by_string.get(s).map(|&i| &self.capabilities[i])
    }
}

fn missing(cap: &Capability, field: &'static str) -> DbError {
    DbError::MissingField {
        capability: cap.id.clone(),
        field,
    }
}

/// Best-effort line number for a duplicate: its last occurrence in the text.
fn line_of(text: &str, word: &str) -> usize {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#'))
        .filter(|(_, l)| {
            l.split(|c: char| c.is_whitespace() || c == '=')
                .any(|w| w == word)
        })
        .map(|(i, _)| i + 1)
        .last()
        .unwrap_or(0)
}

fn append_value(cap: &mut Capability, key: &str, value: &str, line: usize) -> Result<(), DbError> {
    match key {
        "title" | "rationale" => {
            let field = if key == "title" {
                &mut cap.title
            } else {
                &mut cap.rationale
            };
            if !field.is_empty() {
                field.push(' ');
            }
            field.push_str(value);
        }
        "symbols" => cap
            .symbols
            .extend(value.split_whitespace().map(String::from)),
        "strings" => cap
            .strings
            .extend(value.split_whitespace().map(String::from)),
        _ => {
            return Err(DbError::Syntax {
                line,
                message: format!("unknown key '{key}'"),
            })
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_database_is_valid_and_documented() {
        let db = CapDb::builtin();
        assert!(db.capabilities().len() >= 8);
        for cap in db.capabilities() {
            assert!(
                cap.rationale.split_whitespace().count() >= 20,
                "{} needs a real rationale",
                cap.id
            );
        }
        assert_eq!(
            db.for_symbol("xcb_convert_selection").unwrap().id,
            "selection-read"
        );
        assert_eq!(
            db.for_symbol("XRecordEnableContext").unwrap().id,
            "input-record"
        );
        assert_eq!(
            db.for_string("org.freedesktop.portal.ScreenCast")
                .unwrap()
                .id,
            "portal-screencast"
        );
        assert!(db.for_symbol("printf").is_none());
    }

    #[test]
    fn continuation_lines_extend_the_previous_key() {
        let db = CapDb::parse("[a]\ntitle = T\nrationale = one\n  two\nsymbols = s1\n  s2 s3\n")
            .unwrap();
        let cap = db.get("a").unwrap();
        assert_eq!(cap.rationale, "one two");
        assert_eq!(cap.symbols, ["s1", "s2", "s3"]);
    }

    #[test]
    fn rejects_malformed_databases() {
        let dup_symbol =
            "[a]\ntitle=t\nrationale=r\nsymbols=x\n[b]\ntitle=t\nrationale=r\nsymbols=x\n";
        assert!(matches!(
            CapDb::parse(dup_symbol),
            Err(DbError::Duplicate { line: 8, .. })
        ));
        let dup_id = "[a]\ntitle=t\nrationale=r\nsymbols=x\n[a]\n";
        assert!(matches!(
            CapDb::parse(dup_id),
            Err(DbError::Duplicate { line: 5, .. })
        ));
        assert!(matches!(
            CapDb::parse("[a]\ntitle=t\nsymbols=x\n"),
            Err(DbError::MissingField {
                field: "rationale",
                ..
            })
        ));
        assert!(matches!(
            CapDb::parse("[a]\ntitle=t\nrationale=r\n"),
            Err(DbError::MissingField { .. })
        ));
        assert!(matches!(
            CapDb::parse("[a]\ncolour=red\n"),
            Err(DbError::Syntax { line: 2, .. })
        ));
        assert!(matches!(
            CapDb::parse("title=t\n"),
            Err(DbError::Syntax { line: 1, .. })
        ));
        assert!(matches!(
            CapDb::parse("  stray\n"),
            Err(DbError::Syntax { line: 1, .. })
        ));
        assert!(matches!(
            CapDb::parse("[bad id]\n"),
            Err(DbError::Syntax { .. })
        ));
    }
}
