//! Compares the capabilities of two scans of the same application.

use crate::analysis::Confidence;
use crate::scan::Report;
use std::collections::{BTreeMap, BTreeSet};

/// One piece of evidence, without the load chains, which change with every
/// reshuffle of a bundle's directory layout.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceKey {
    pub object: String,
    pub symbol: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityChange {
    pub capability: String,
    pub title: String,
    pub evidence: Vec<EvidenceKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceChange {
    pub capability: String,
    pub title: String,
    pub added: Vec<EvidenceKey>,
    pub removed: Vec<EvidenceKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Diff {
    /// Capabilities with evidence in `new` and none in `old`.
    pub added: Vec<CapabilityChange>,
    /// Capabilities with evidence in `old` and none in `new`.
    pub removed: Vec<CapabilityChange>,
    /// Capabilities present in both whose evidence differs.
    pub changed: Vec<EvidenceChange>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

type Grouped = BTreeMap<String, (String, BTreeSet<EvidenceKey>)>;

fn group(report: &Report) -> Grouped {
    let mut grouped = Grouped::new();
    for f in &report.findings {
        grouped
            .entry(f.capability.clone())
            .or_insert_with(|| (f.title.clone(), BTreeSet::new()))
            .1
            .insert(EvidenceKey {
                object: f.object.clone(),
                symbol: f.symbol.clone(),
                confidence: f.confidence,
            });
    }
    grouped
}

pub fn diff(old: &Report, new: &Report) -> Diff {
    let old = group(old);
    let new = group(new);
    let mut result = Diff::default();
    for (capability, (title, evidence)) in &new {
        match old.get(capability) {
            None => result.added.push(CapabilityChange {
                capability: capability.clone(),
                title: title.clone(),
                evidence: evidence.iter().cloned().collect(),
            }),
            Some((_, old_evidence)) if old_evidence != evidence => {
                result.changed.push(EvidenceChange {
                    capability: capability.clone(),
                    title: title.clone(),
                    added: evidence.difference(old_evidence).cloned().collect(),
                    removed: old_evidence.difference(evidence).cloned().collect(),
                })
            }
            Some(_) => {}
        }
    }
    for (capability, (title, evidence)) in &old {
        if !new.contains_key(capability) {
            result.removed.push(CapabilityChange {
                capability: capability.clone(),
                title: title.clone(),
                evidence: evidence.iter().cloned().collect(),
            });
        }
    }
    result
}
