//! The diff itself: what changed between two SBOMs, and how much each
//! change needs a person to look at it.

use crate::license::Category;
use crate::sbom::{Component, Licenses, Sbom};
use crate::version;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Downgraded,
    OlderCopyAdded,
    LicenseChanged,
    Added,
    VersionOrderUnknown,
    Upgraded,
    Relabelled,
    Removed,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::Downgraded => "downgraded",
            Rule::OlderCopyAdded => "older-copy-added",
            Rule::LicenseChanged => "license-changed",
            Rule::Added => "added",
            Rule::VersionOrderUnknown => "version-order-unknown",
            Rule::Upgraded => "upgraded",
            Rule::Relabelled => "relabelled",
            Rule::Removed => "removed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub rule: Rule,
    pub component: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub detail: String,
}

type Versions<'a> = BTreeMap<&'a str, &'a Component>;

pub fn diff(before: &Sbom, after: &Sbom) -> Vec<Finding> {
    let b = index(before);
    let a = index(after);
    let empty = Versions::new();
    let keys: BTreeSet<&str> = b.keys().chain(a.keys()).copied().collect();

    let mut out = Vec::new();
    for key in keys {
        compare_package(
            key,
            b.get(key).unwrap_or(&empty),
            a.get(key).unwrap_or(&empty),
            &mut out,
        );
    }
    out.sort_by(|x, y| {
        y.severity
            .cmp(&x.severity)
            .then_with(|| x.component.cmp(&y.component))
            .then_with(|| x.rule.cmp(&y.rule))
            .then_with(|| x.before.cmp(&y.before))
            .then_with(|| x.after.cmp(&y.after))
    });
    out
}

/// One package can be present at several versions at once (npm nests a
/// second copy when two dependents disagree), so each identity maps to a
/// *set* of versions -- a name -> version map would silently keep one copy
/// and drop the rest. See ADR 1.
fn index(sbom: &Sbom) -> BTreeMap<&str, Versions<'_>> {
    let mut map: BTreeMap<&str, Versions<'_>> = BTreeMap::new();
    for c in &sbom.components {
        map.entry(c.key.as_str())
            .or_default()
            .entry(c.version.as_str())
            .or_insert(c);
    }
    map
}

fn compare_package(key: &str, before: &Versions<'_>, after: &Versions<'_>, out: &mut Vec<Finding>) {
    if before.is_empty() {
        for c in after.values() {
            out.push(added(key, c, None));
        }
        return;
    }
    if after.is_empty() {
        for c in before.values() {
            out.push(removed(key, c, None));
        }
        return;
    }

    if before.len() == 1 && after.len() == 1 {
        let (&old_v, &old) = before.iter().next().expect("len checked");
        let (&new_v, &new) = after.iter().next().expect("len checked");
        if old_v != new_v {
            out.push(version_change(key, old_v, new_v));
        }
        out.extend(license_change(key, old, new));
        return;
    }

    // Several copies on at least one side.
    for (v, old) in before {
        if let Some(new) = after.get(v) {
            out.extend(license_change(key, old, new));
        }
    }
    let highest_before = highest(before.keys().copied());
    for (v, c) in after {
        if before.contains_key(v) {
            continue;
        }
        let older = highest_before.is_some_and(|h| version::compare(v, h) == Some(Ordering::Less));
        if older {
            out.push(older_copy_added(key, c, before));
        } else {
            out.push(added(key, c, Some(before)));
        }
    }
    for (v, c) in before {
        if !after.contains_key(v) {
            out.push(removed(key, c, Some(after)));
        }
    }
    if let (Some(hb), Some(ha)) = (highest_before, highest(after.keys().copied())) {
        if version::compare(ha, hb) == Some(Ordering::Less) {
            out.push(Finding {
                severity: Severity::High,
                rule: Rule::Downgraded,
                component: key.to_string(),
                before: Some(hb.to_string()),
                after: Some(ha.to_string()),
                detail: format!("highest copy went from {hb} to {ha}"),
            });
        }
    }
}

/// The highest of a set of versions, or `None` if any pair can't be
/// ordered -- in which case nobody should be told something was downgraded.
fn highest<'a>(mut versions: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let first = versions.next()?;
    versions.try_fold(first, |best, v| match version::compare(v, best)? {
        Ordering::Greater => Some(v),
        _ => Some(best),
    })
}

fn list(versions: &Versions<'_>) -> String {
    versions.keys().copied().collect::<Vec<_>>().join(", ")
}

fn category_severity(category: Option<Category>) -> Severity {
    match category {
        None => Severity::Medium, // no licence declared is not permission to use
        Some(Category::Permissive) => Severity::Info,
        Some(Category::WeakCopyleft) | Some(Category::Unrecognised) => Severity::Medium,
        Some(Category::StrongCopyleft) | Some(Category::SourceAvailable) => Severity::High,
    }
}

fn licence_note(l: &Licenses) -> String {
    match l.category {
        Some(cat) => format!("{}, {}", l.describe(), cat),
        None => l.describe(),
    }
}

fn added(key: &str, c: &Component, alongside: Option<&Versions<'_>>) -> Finding {
    let mut detail = format!(
        "{} ({})",
        display_version(&c.version),
        licence_note(&c.licenses)
    );
    if let Some(existing) = alongside {
        detail.push_str(&format!(", alongside {}", list(existing)));
    }
    Finding {
        severity: category_severity(c.licenses.category),
        rule: Rule::Added,
        component: key.to_string(),
        before: None,
        after: Some(c.version.clone()),
        detail,
    }
}

fn older_copy_added(key: &str, c: &Component, existing: &Versions<'_>) -> Finding {
    Finding {
        // An older duplicate is how a fixed vulnerability comes back while
        // the "main" copy stays current and every dashboard looks fine.
        severity: Severity::Medium.max(category_severity(c.licenses.category)),
        rule: Rule::OlderCopyAdded,
        component: key.to_string(),
        before: None,
        after: Some(c.version.clone()),
        detail: format!(
            "{} added alongside newer {} ({})",
            c.version,
            list(existing),
            licence_note(&c.licenses)
        ),
    }
}

fn removed(key: &str, c: &Component, remaining: Option<&Versions<'_>>) -> Finding {
    let mut detail = display_version(&c.version).to_string();
    if let Some(rest) = remaining {
        detail.push_str(&format!(" removed, {} remain", list(rest)));
    }
    Finding {
        severity: Severity::Info,
        rule: Rule::Removed,
        component: key.to_string(),
        before: Some(c.version.clone()),
        after: None,
        detail,
    }
}

fn version_change(key: &str, old: &str, new: &str) -> Finding {
    let (severity, rule, detail) = match version::compare(new, old) {
        Some(Ordering::Greater) => (Severity::Info, Rule::Upgraded, format!("{old} -> {new}")),
        Some(Ordering::Less) => (Severity::High, Rule::Downgraded, format!("{old} -> {new}")),
        Some(Ordering::Equal) => (
            Severity::Info,
            Rule::Relabelled,
            format!("{old} -> {new}, same release precedence"),
        ),
        None => (
            Severity::Low,
            Rule::VersionOrderUnknown,
            format!("{old} -> {new}, direction unknown"),
        ),
    };
    Finding {
        severity,
        rule,
        component: key.to_string(),
        before: Some(old.to_string()),
        after: Some(new.to_string()),
        detail,
    }
}

fn license_change(key: &str, old: &Component, new: &Component) -> Option<Finding> {
    let (o, n) = (&old.licenses, &new.licenses);
    if o.declared == n.declared {
        return None;
    }
    let severity = match (o.category, n.category) {
        (Some(_), None) => Severity::Medium,
        (None, Some(cat)) => category_severity(Some(cat)),
        (Some(was), Some(now)) if now > was => category_severity(Some(now)),
        _ => Severity::Low,
    };
    Some(Finding {
        severity,
        rule: Rule::LicenseChanged,
        component: key.to_string(),
        before: Some(old.version.clone()),
        after: Some(new.version.clone()),
        detail: format!("{} -> {}", licence_note(o), licence_note(n)),
    })
}

fn display_version(v: &str) -> &str {
    if v.is_empty() {
        "(no version)"
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::classify_id;

    fn comp(key: &str, version: &str, license: Option<&str>) -> Component {
        Component {
            key: key.into(),
            version: version.into(),
            licenses: Licenses {
                declared: license.map(|l| vec![l.to_string()]).unwrap_or_default(),
                category: license.map(classify_id),
            },
        }
    }

    fn sbom(components: Vec<Component>) -> Sbom {
        Sbom {
            spec_version: "1.5".into(),
            subject: None,
            components,
        }
    }

    fn rules(findings: &[Finding]) -> Vec<(&str, &str, Severity)> {
        findings
            .iter()
            .map(|f| (f.rule.id(), f.component.as_str(), f.severity))
            .collect()
    }

    #[test]
    fn identical_sboms_have_no_findings() {
        let s = sbom(vec![comp("npm/a", "1.0.0", Some("MIT"))]);
        assert!(diff(&s, &s).is_empty());
    }

    #[test]
    fn upgrade_is_info_and_downgrade_is_high() {
        let before = sbom(vec![
            comp("npm/a", "1.0.0", Some("MIT")),
            comp("npm/b", "2.0.0", Some("MIT")),
        ]);
        let after = sbom(vec![
            comp("npm/a", "1.1.0", Some("MIT")),
            comp("npm/b", "1.9.0", Some("MIT")),
        ]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [
                ("downgraded", "npm/b", Severity::High),
                ("upgraded", "npm/a", Severity::Info)
            ]
        );
    }

    #[test]
    fn unorderable_versions_are_reported_without_a_direction() {
        let before = sbom(vec![comp("maven/x/y", "1.0.Final", Some("MIT"))]);
        let after = sbom(vec![comp("maven/x/y", "1.0.1", Some("MIT"))]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [("version-order-unknown", "maven/x/y", Severity::Low)]
        );
    }

    #[test]
    fn added_severity_follows_the_new_components_licence() {
        let before = sbom(vec![]);
        let after = sbom(vec![
            comp("npm/mit", "1", Some("MIT")),
            comp("npm/gpl", "1", Some("GPL-3.0-only")),
            comp("npm/none", "1", None),
            comp("npm/mpl", "1", Some("MPL-2.0")),
        ]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [
                ("added", "npm/gpl", Severity::High),
                ("added", "npm/mpl", Severity::Medium),
                ("added", "npm/none", Severity::Medium),
                ("added", "npm/mit", Severity::Info),
            ]
        );
    }

    #[test]
    fn licence_becoming_more_restrictive_is_graded_by_where_it_landed() {
        let before = sbom(vec![comp("npm/tinymce", "6.8.5", Some("MIT"))]);
        let after = sbom(vec![comp("npm/tinymce", "7.6.0", Some("GPL-2.0-or-later"))]);
        let findings = diff(&before, &after);
        assert_eq!(
            rules(&findings),
            [
                ("license-changed", "npm/tinymce", Severity::High),
                ("upgraded", "npm/tinymce", Severity::Info)
            ]
        );
        assert_eq!(
            findings[0].detail,
            "MIT, permissive -> GPL-2.0-or-later, strong copyleft"
        );
    }

    #[test]
    fn licence_becoming_less_restrictive_is_low() {
        let before = sbom(vec![comp("npm/a", "1", Some("GPL-3.0-only"))]);
        let after = sbom(vec![comp("npm/a", "1", Some("MIT"))]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [("license-changed", "npm/a", Severity::Low)]
        );
    }

    #[test]
    fn a_dropped_licence_declaration_is_medium() {
        let before = sbom(vec![comp("npm/a", "1", Some("MIT"))]);
        let after = sbom(vec![comp("npm/a", "1", None)]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [("license-changed", "npm/a", Severity::Medium)]
        );
    }

    #[test]
    fn an_older_second_copy_is_flagged_even_though_the_newest_is_unchanged() {
        let before = sbom(vec![comp("npm/qs", "6.13.0", Some("BSD-3-Clause"))]);
        let after = sbom(vec![
            comp("npm/qs", "6.13.0", Some("BSD-3-Clause")),
            comp("npm/qs", "6.11.0", Some("BSD-3-Clause")),
        ]);
        let findings = diff(&before, &after);
        assert_eq!(
            rules(&findings),
            [("older-copy-added", "npm/qs", Severity::Medium)]
        );
        assert_eq!(
            findings[0].detail,
            "6.11.0 added alongside newer 6.13.0 (BSD-3-Clause, permissive)"
        );
    }

    #[test]
    fn a_newer_second_copy_is_just_added() {
        let before = sbom(vec![comp("npm/ms", "2.0.0", Some("MIT"))]);
        let after = sbom(vec![
            comp("npm/ms", "2.0.0", Some("MIT")),
            comp("npm/ms", "2.1.3", Some("MIT")),
        ]);
        assert_eq!(
            rules(&diff(&before, &after)),
            [("added", "npm/ms", Severity::Info)]
        );
    }

    #[test]
    fn losing_the_highest_copy_counts_as_a_downgrade() {
        let before = sbom(vec![
            comp("npm/ms", "2.0.0", Some("MIT")),
            comp("npm/ms", "2.1.3", Some("MIT")),
        ]);
        let after = sbom(vec![comp("npm/ms", "2.0.0", Some("MIT"))]);
        let findings = diff(&before, &after);
        assert_eq!(
            rules(&findings),
            [
                ("downgraded", "npm/ms", Severity::High),
                ("removed", "npm/ms", Severity::Info)
            ]
        );
        assert_eq!(findings[0].detail, "highest copy went from 2.1.3 to 2.0.0");
    }

    #[test]
    fn removed_package_is_info() {
        let before = sbom(vec![comp("npm/gone", "1.0.0", Some("MIT"))]);
        assert_eq!(
            rules(&diff(&before, &sbom(vec![]))),
            [("removed", "npm/gone", Severity::Info)]
        );
    }

    #[test]
    fn duplicate_entries_of_the_same_version_count_once() {
        let before = sbom(vec![]);
        let after = sbom(vec![
            comp("npm/a", "1", Some("MIT")),
            comp("npm/a", "1", Some("MIT")),
        ]);
        assert_eq!(diff(&before, &after).len(), 1);
    }

    #[test]
    fn severity_parses_case_insensitively() {
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("critical"), None);
    }
}
