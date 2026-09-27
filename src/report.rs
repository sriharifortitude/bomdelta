use crate::diff::{Finding, Severity};
use crate::sbom::Sbom;
use serde_json::json;

pub struct Report<'a> {
    pub before: &'a Sbom,
    pub after: &'a Sbom,
    pub findings: &'a [Finding],
    /// `None` means `--fail-on none`: report everything, never fail.
    pub fail_on: Option<Severity>,
}

impl Report<'_> {
    pub fn failing(&self) -> usize {
        match self.fail_on {
            Some(level) => self.findings.iter().filter(|f| f.severity >= level).count(),
            None => 0,
        }
    }

    fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    fn subject_line(&self) -> String {
        let name = |s: &Sbom| {
            s.subject
                .clone()
                .unwrap_or_else(|| "(no metadata.component)".into())
        };
        format!("{} -> {}", name(self.before), name(self.after))
    }

    fn counts(&self) -> String {
        format!(
            "{} high, {} medium, {} low, {} info",
            self.count(Severity::High),
            self.count(Severity::Medium),
            self.count(Severity::Low),
            self.count(Severity::Info)
        )
    }

    fn verdict(&self) -> String {
        match self.fail_on {
            None => "--fail-on none: reporting only.".into(),
            Some(level) => match self.failing() {
                0 => format!("Nothing at or above {}.", level.label()),
                1 => format!("Failing: 1 change at or above {}.", level.label()),
                n => format!("Failing: {n} changes at or above {}.", level.label()),
            },
        }
    }

    pub fn terminal(&self) -> String {
        let mut out = format!(
            "bomdelta: {}\n          {} -> {} components (CycloneDX {} -> {})\n\n",
            self.subject_line(),
            self.before.components.len(),
            self.after.components.len(),
            self.before.spec_version,
            self.after.spec_version
        );
        if self.findings.is_empty() {
            out.push_str("No dependency changes.\n");
            return out;
        }
        let rule_w = self
            .findings
            .iter()
            .map(|f| f.rule.id().len())
            .max()
            .unwrap_or(0);
        let comp_w = self
            .findings
            .iter()
            .map(|f| f.component.len())
            .max()
            .unwrap_or(0);
        for f in self.findings {
            out.push_str(&format!(
                "{:<7} {:<rule_w$}  {:<comp_w$}  {}\n",
                f.severity.label().to_ascii_uppercase(),
                f.rule.id(),
                f.component,
                f.detail
            ));
        }
        out.push_str(&format!(
            "\n{} changes: {}. {}\n",
            self.findings.len(),
            self.counts(),
            self.verdict()
        ));
        out
    }

    pub fn markdown(&self) -> String {
        let mut out = format!(
            "### bomdelta: {}\n\n{} -> {} components. {} changes: {}. {}\n",
            self.subject_line(),
            self.before.components.len(),
            self.after.components.len(),
            self.findings.len(),
            self.counts(),
            self.verdict()
        );
        if self.findings.is_empty() {
            return out;
        }
        out.push_str("\n| Severity | Change | Component | Detail |\n| --- | --- | --- | --- |\n");
        for f in self.findings {
            out.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                f.severity.label(),
                f.rule.id(),
                f.component,
                f.detail.replace('|', "\\|")
            ));
        }
        out
    }

    pub fn json(&self) -> String {
        let findings: Vec<_> = self
            .findings
            .iter()
            .map(|f| {
                json!({
                    "severity": f.severity.label(),
                    "rule": f.rule.id(),
                    "component": f.component,
                    "before": f.before,
                    "after": f.after,
                    "detail": f.detail,
                })
            })
            .collect();
        let doc = json!({
            "before": { "subject": self.before.subject, "specVersion": self.before.spec_version, "components": self.before.components.len() },
            "after": { "subject": self.after.subject, "specVersion": self.after.spec_version, "components": self.after.components.len() },
            "failOn": self.fail_on.map(Severity::label),
            "failing": self.failing(),
            "findings": findings,
        });
        let mut text = serde_json::to_string_pretty(&doc).expect("serialising a Value cannot fail");
        text.push('\n');
        text
    }
}
