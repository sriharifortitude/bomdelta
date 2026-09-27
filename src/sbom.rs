//! Loading a CycloneDX JSON SBOM into the few fields a diff needs.

use crate::license::{self, Category};
use crate::purl;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Licenses {
    /// What the SBOM said, verbatim, for display.
    pub declared: Vec<String>,
    /// `None` when nothing was declared at all -- a different finding from
    /// "declared, but not something we recognise".
    pub category: Option<Category>,
}

impl Licenses {
    pub fn describe(&self) -> String {
        if self.declared.is_empty() {
            "no licence declared".to_string()
        } else {
            self.declared.join(" AND ")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Identity across versions: the purl minus version, qualifiers and
    /// subpath when there is one, otherwise group/name.
    pub key: String,
    pub version: String,
    pub licenses: Licenses,
}

#[derive(Debug, Clone)]
pub struct Sbom {
    pub spec_version: String,
    /// The product the SBOM describes (metadata.component), kept out of
    /// the dependency diff: its own version bump is the release, not a
    /// change to review.
    pub subject: Option<String>,
    pub components: Vec<Component>,
}

#[derive(Debug)]
pub enum LoadError {
    NotJson(String),
    NotCycloneDx(String),
    UnsupportedSpec(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::NotJson(e) => write!(f, "not valid JSON: {e}"),
            LoadError::NotCycloneDx(why) => write!(f, "not a CycloneDX JSON SBOM: {why}"),
            LoadError::UnsupportedSpec(v) => {
                write!(
                    f,
                    "CycloneDX specVersion {v} is not supported (1.2 to 1.6 are)"
                )
            }
        }
    }
}

const SUPPORTED_SPECS: &[&str] = &["1.2", "1.3", "1.4", "1.5", "1.6"];

pub fn parse(text: &str) -> Result<Sbom, LoadError> {
    let doc: Value = serde_json::from_str(text).map_err(|e| LoadError::NotJson(e.to_string()))?;

    if doc.get("spdxVersion").is_some() {
        return Err(LoadError::NotCycloneDx(
            "this is SPDX JSON; bomdelta reads CycloneDX only (most SBOM generators can emit either)".into(),
        ));
    }
    if doc.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err(LoadError::NotCycloneDx(
            "missing \"bomFormat\": \"CycloneDX\"".into(),
        ));
    }
    let spec_version = doc
        .get("specVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| LoadError::NotCycloneDx("missing specVersion".into()))?
        .to_string();
    if !SUPPORTED_SPECS.contains(&spec_version.as_str()) {
        return Err(LoadError::UnsupportedSpec(spec_version));
    }

    let subject = doc.pointer("/metadata/component").map(|c| {
        let name = c.get("name").and_then(Value::as_str).unwrap_or("(unnamed)");
        match c.get("version").and_then(Value::as_str) {
            Some(v) => format!("{name} {v}"),
            None => name.to_string(),
        }
    });

    let mut components = Vec::new();
    if let Some(list) = doc.get("components").and_then(Value::as_array) {
        collect(list, &mut components);
    }
    Ok(Sbom {
        spec_version,
        subject,
        components,
    })
}

/// CycloneDX lets a component contain components (an application bundling
/// its libraries, a container image and its packages). They're all
/// dependencies of the release, so they're flattened into one list.
fn collect(list: &[Value], out: &mut Vec<Component>) {
    for c in list {
        // A per-file listing is a different review from a dependency diff,
        // and some generators emit thousands of them.
        if c.get("type").and_then(Value::as_str) != Some("file") {
            if let Some(component) = component(c) {
                out.push(component);
            }
        }
        if let Some(children) = c.get("components").and_then(Value::as_array) {
            collect(children, out);
        }
    }
}

fn component(c: &Value) -> Option<Component> {
    let name = c.get("name").and_then(Value::as_str)?;
    let parsed_purl = c.get("purl").and_then(Value::as_str).and_then(purl::parse);
    let key = match &parsed_purl {
        Some(p) => p.identity(),
        None => match c
            .get("group")
            .and_then(Value::as_str)
            .filter(|g| !g.is_empty())
        {
            Some(group) => format!("{group}/{name}"),
            None => name.to_string(),
        },
    };
    let version = c
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| parsed_purl.and_then(|p| p.version))
        .unwrap_or_default();
    Some(Component {
        key,
        version,
        licenses: licenses(c),
    })
}

/// Several entries in `licenses` are read as all applying (AND). The
/// CycloneDX schema doesn't say whether a list is a conjunction or a
/// choice; treating it as a choice could hide a copyleft licence behind a
/// permissive one, and the cost of the other mistake is only a review.
fn licenses(c: &Value) -> Licenses {
    let mut declared = Vec::new();
    let mut category: Option<Category> = None;
    for entry in c
        .get("licenses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (text, cat) = if let Some(expr) = entry.get("expression").and_then(Value::as_str) {
            (expr.to_string(), license::classify_expression(expr))
        } else if let Some(id) = entry.pointer("/license/id").and_then(Value::as_str) {
            (id.to_string(), license::classify_id(id))
        } else if let Some(name) = entry.pointer("/license/name").and_then(Value::as_str) {
            (name.to_string(), Category::Unrecognised)
        } else {
            continue;
        };
        declared.push(text);
        category = Some(category.map_or(cat, |c| c.max(cat)));
    }
    Licenses { declared, category }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bom(components: &str) -> String {
        format!(r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":{components}}}"#)
    }

    #[test]
    fn reads_key_version_and_licence() {
        let sbom = parse(&bom(
            r#"[{"type":"library","name":"express","version":"4.21.2","purl":"pkg:npm/express@4.21.2","licenses":[{"license":{"id":"MIT"}}]}]"#,
        ))
        .unwrap();
        let c = &sbom.components[0];
        assert_eq!(c.key, "npm/express");
        assert_eq!(c.version, "4.21.2");
        assert_eq!(c.licenses.category, Some(Category::Permissive));
    }

    #[test]
    fn flattens_nested_components() {
        let sbom = parse(&bom(
            r#"[{"type":"application","name":"app","version":"1","components":[{"type":"library","name":"inner","version":"2"}]}]"#,
        ))
        .unwrap();
        let keys: Vec<_> = sbom.components.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["app", "inner"]);
    }

    #[test]
    fn skips_file_components_but_not_their_children() {
        let sbom = parse(&bom(
            r#"[{"type":"file","name":"a.txt","components":[{"type":"library","name":"lib","version":"1"}]}]"#,
        ))
        .unwrap();
        let keys: Vec<_> = sbom.components.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["lib"]);
    }

    #[test]
    fn falls_back_to_group_and_name_without_a_purl() {
        let sbom = parse(&bom(
            r#"[{"type":"library","group":"org.example","name":"thing","version":"1.0"}]"#,
        ))
        .unwrap();
        assert_eq!(sbom.components[0].key, "org.example/thing");
    }

    #[test]
    fn takes_the_version_from_the_purl_when_the_field_is_missing() {
        let sbom = parse(&bom(
            r#"[{"type":"library","name":"x","purl":"pkg:npm/x@1.2.3"}]"#,
        ))
        .unwrap();
        assert_eq!(sbom.components[0].version, "1.2.3");
    }

    #[test]
    fn multiple_licence_entries_all_apply() {
        let sbom = parse(&bom(
            r#"[{"type":"library","name":"x","version":"1","licenses":[{"license":{"id":"MIT"}},{"license":{"id":"GPL-3.0-only"}}]}]"#,
        ))
        .unwrap();
        assert_eq!(
            sbom.components[0].licenses.category,
            Some(Category::StrongCopyleft)
        );
    }

    #[test]
    fn distinguishes_no_licence_from_an_unrecognised_one() {
        let sbom = parse(&bom(
            r#"[{"type":"library","name":"a","version":"1"},{"type":"library","name":"b","version":"1","licenses":[{"license":{"name":"Custom"}}]}]"#,
        ))
        .unwrap();
        assert_eq!(sbom.components[0].licenses.category, None);
        assert_eq!(
            sbom.components[1].licenses.category,
            Some(Category::Unrecognised)
        );
    }

    #[test]
    fn reads_licence_expressions() {
        let sbom = parse(&bom(r#"[{"type":"library","name":"x","version":"1","licenses":[{"expression":"MIT OR GPL-2.0-only"}]}]"#))
            .unwrap();
        assert_eq!(
            sbom.components[0].licenses.category,
            Some(Category::Permissive)
        );
    }

    #[test]
    fn keeps_the_product_itself_out_of_the_component_list() {
        let text = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"demo-app","version":"1.0.0"}},"components":[]}"#;
        let sbom = parse(text).unwrap();
        assert_eq!(sbom.subject.as_deref(), Some("demo-app 1.0.0"));
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn rejects_spdx_with_a_useful_message() {
        let err = parse(r#"{"spdxVersion":"SPDX-2.3","packages":[]}"#).unwrap_err();
        assert!(err.to_string().contains("SPDX"), "{err}");
    }

    #[test]
    fn rejects_unsupported_spec_versions_and_non_json() {
        assert!(matches!(
            parse(r#"{"bomFormat":"CycloneDX","specVersion":"2.0"}"#),
            Err(LoadError::UnsupportedSpec(_))
        ));
        assert!(matches!(parse("not json"), Err(LoadError::NotJson(_))));
        assert!(matches!(
            parse(r#"{"bomFormat":"Other","specVersion":"1.5"}"#),
            Err(LoadError::NotCycloneDx(_))
        ));
    }
}
