//! Text and JSON rendering. JSON is written by hand to keep the crate free of
//! dependencies; the structures are flat enough that this stays readable.

use crate::capdb::CapDb;
use crate::diff::{Diff, EvidenceKey};
use crate::scan::{Finding, Report};
use std::collections::BTreeSet;
use std::fmt::Write;

pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt(s: &Option<String>) -> String {
    s.as_deref().map_or_else(|| "null".to_string(), json_string)
}

fn json_list<T>(items: &[T], f: impl Fn(&T) -> String) -> String {
    let parts: Vec<String> = items.iter().map(f).collect();
    format!("[{}]", parts.join(","))
}

fn json_chain(chain: &[String]) -> String {
    json_list(chain, |s| json_string(s))
}

pub fn report_json(report: &Report) -> String {
    let objects = json_list(&report.objects, |o| {
        format!(
            "{{\"path\":{},\"executable\":{},\"format\":{},\"machine\":{},\"soname\":{},\"rpath\":{},\"runpath\":{},\"needed\":{},\"imports_dynamic_loader\":{},\"dlopen_candidates\":{}}}",
            json_string(&o.path),
            o.executable,
            json_string(&o.format),
            o.machine,
            json_opt(&o.soname),
            json_opt(&o.rpath),
            json_opt(&o.runpath),
            json_list(&o.needed, |n| format!(
                "{{\"name\":{},\"resolved\":{}}}",
                json_string(&n.name),
                json_opt(&n.resolved)
            )),
            o.imports_dynamic_loader,
            json_chain(&o.dlopen_candidates),
        )
    });
    let findings = json_list(&report.findings, |f| {
        format!(
            "{{\"capability\":{},\"title\":{},\"object\":{},\"symbol\":{},\"version\":{},\"confidence\":{},\"reached_via\":{}}}",
            json_string(&f.capability),
            json_string(&f.title),
            json_string(&f.object),
            json_string(&f.symbol),
            json_opt(&f.version),
            json_string(f.confidence.as_str()),
            json_list(&f.reached_via, |c| json_chain(c)),
        )
    });
    let errors = json_list(&report.errors, |e| {
        format!(
            "{{\"path\":{},\"message\":{}}}",
            json_string(&e.path),
            json_string(&e.message)
        )
    });
    format!(
        "{{\"root\":{},\"objects\":{},\"findings\":{},\"errors\":{}}}\n",
        json_string(&report.root),
        objects,
        findings,
        errors
    )
}

fn evidence_json(e: &EvidenceKey) -> String {
    format!(
        "{{\"object\":{},\"symbol\":{},\"confidence\":{}}}",
        json_string(&e.object),
        json_string(&e.symbol),
        json_string(e.confidence.as_str())
    )
}

pub fn diff_json(diff: &Diff) -> String {
    let change = |c: &crate::diff::CapabilityChange| {
        format!(
            "{{\"capability\":{},\"title\":{},\"evidence\":{}}}",
            json_string(&c.capability),
            json_string(&c.title),
            json_list(&c.evidence, evidence_json)
        )
    };
    let changed = json_list(&diff.changed, |c| {
        format!(
            "{{\"capability\":{},\"title\":{},\"added\":{},\"removed\":{}}}",
            json_string(&c.capability),
            json_string(&c.title),
            json_list(&c.added, evidence_json),
            json_list(&c.removed, evidence_json)
        )
    });
    format!(
        "{{\"added\":{},\"removed\":{},\"changed\":{}}}\n",
        json_list(&diff.added, change),
        json_list(&diff.removed, change),
        changed
    )
}

fn via_text(finding: &Finding, report: &Report) -> String {
    let Some(first) = finding.reached_via.first() else {
        return String::new();
    };
    let head_is_executable = first
        .first()
        .and_then(|head| report.objects.iter().find(|o| &o.path == head))
        .is_some_and(|o| o.executable);
    let mut text = if first.len() == 1 && head_is_executable {
        "(executable)".to_string()
    } else if first.len() == 1 {
        "(not linked from any executable)".to_string()
    } else {
        let chain = first.join(" -> ");
        if head_is_executable {
            chain
        } else {
            format!("{chain} (no executable)")
        }
    };
    if finding.reached_via.len() > 1 {
        let _ = write!(text, " (+{} more)", finding.reached_via.len() - 1);
    }
    text
}

fn table(rows: &[Vec<String>]) -> String {
    let columns = rows.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..columns)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (c, cell) in row.iter().enumerate() {
            if c + 1 == columns {
                line.push_str(cell);
            } else {
                let _ = write!(line, "{:width$}  ", cell, width = widths[c]);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

pub fn report_text(report: &Report, db: &CapDb) -> String {
    let mut out = String::new();
    let executables = report.objects.iter().filter(|o| o.executable).count();
    let capabilities: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|f| f.capability.as_str())
        .collect();
    let _ = writeln!(
        out,
        "Scanned {}: {} ELF objects ({} executable), {} findings in {} capabilities.\n",
        report.root,
        report.objects.len(),
        executables,
        report.findings.len(),
        capabilities.len()
    );

    if report.findings.is_empty() {
        out.push_str("No imports or strings from the capability database were found.\n");
    } else {
        let mut rows = vec![[
            "CAPABILITY",
            "OBJECT",
            "SYMBOL",
            "CONFIDENCE",
            "REACHED VIA",
        ]
        .map(String::from)
        .to_vec()];
        for f in &report.findings {
            let symbol = match &f.version {
                Some(v) => format!("{}@{}", f.symbol, v),
                None => f.symbol.clone(),
            };
            rows.push(vec![
                f.capability.clone(),
                f.object.clone(),
                symbol,
                f.confidence.to_string(),
                via_text(f, report),
            ]);
        }
        out.push_str(&table(&rows));
        out.push_str("\nCapabilities found:\n");
        for cap in db.capabilities() {
            if capabilities.contains(cap.id.as_str()) {
                let _ = writeln!(out, "  {:<22} {}", cap.id, cap.title);
            }
        }
    }

    let dynamic: Vec<_> = report
        .objects
        .iter()
        .filter(|o| !o.dlopen_candidates.is_empty())
        .collect();
    if !dynamic.is_empty() {
        out.push_str("\nLibrary names in objects that import dlopen/dlsym:\n");
        for o in dynamic {
            let _ = writeln!(out, "  {}: {}", o.path, o.dlopen_candidates.join(", "));
        }
    }

    let external: Vec<_> = report
        .objects
        .iter()
        .filter_map(|o| {
            let names: Vec<&str> = o
                .needed
                .iter()
                .filter(|n| n.resolved.is_none())
                .map(|n| n.name.as_str())
                .collect();
            (!names.is_empty()).then_some((o.path.as_str(), names))
        })
        .collect();
    if !external.is_empty() {
        out.push_str("\nDT_NEEDED not found in the bundle (left to the system):\n");
        for (path, names) in external {
            let _ = writeln!(out, "  {}: {}", path, names.join(", "));
        }
    }

    if !report.errors.is_empty() {
        out.push_str("\nCould not load:\n");
        for e in &report.errors {
            let _ = writeln!(out, "  {}: {}", e.path, e.message);
        }
    }
    out
}

pub fn diff_text(diff: &Diff, old: &str, new: &str) -> String {
    let mut out = format!("Capability diff {old} -> {new}\n\n");
    if diff.is_empty() {
        out.push_str("No capability changes.\n");
        return out;
    }
    let evidence_line = |out: &mut String, prefix: &str, e: &EvidenceKey| {
        let _ = writeln!(
            out,
            "    {prefix}{}  {}  {}",
            e.object, e.symbol, e.confidence
        );
    };
    for c in &diff.added {
        let _ = writeln!(out, "+ {}  {}", c.capability, c.title);
        for e in &c.evidence {
            evidence_line(&mut out, "", e);
        }
    }
    for c in &diff.removed {
        let _ = writeln!(out, "- {}  {}", c.capability, c.title);
        for e in &c.evidence {
            evidence_line(&mut out, "", e);
        }
    }
    for c in &diff.changed {
        let _ = writeln!(out, "~ {}  evidence changed", c.capability);
        for e in &c.added {
            evidence_line(&mut out, "+ ", e);
        }
        for e in &c.removed {
            evidence_line(&mut out, "- ", e);
        }
    }
    out
}

pub fn capabilities_text(db: &CapDb) -> String {
    let mut out = String::new();
    for cap in db.capabilities() {
        let _ = writeln!(out, "{}\n  {}", cap.id, cap.title);
        if !cap.symbols.is_empty() {
            let _ = writeln!(out, "  symbols: {}", cap.symbols.join(" "));
        }
        if !cap.strings.is_empty() {
            let _ = writeln!(out, "  strings: {}", cap.strings.join(" "));
        }
        let _ = writeln!(out, "  why: {}\n", cap.rationale);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_control_and_quote_characters() {
        assert_eq!(json_string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(json_string("x\ny\u{1}"), "\"x\\ny\\u0001\"");
        assert_eq!(json_string("libé.so"), "\"libé.so\"");
    }

    #[test]
    fn table_pads_all_but_last_column() {
        let rows = vec![
            vec!["a".to_string(), "bbb".to_string(), "c".to_string()],
            vec!["aaaa".to_string(), "b".to_string(), "cc".to_string()],
        ];
        assert_eq!(table(&rows), "a     bbb  c\naaaa  b    cc\n");
    }
}
