//! Just enough of the Package URL spec (github.com/package-url/purl-spec)
//! to answer one question: are these two components the same package?

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purl {
    pub ptype: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
}

impl Purl {
    /// Type, namespace and name -- everything that names the package, and
    /// nothing (version, qualifiers, subpath) that names one build of it.
    pub fn identity(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}/{}", self.ptype, ns, self.name),
            None => format!("{}/{}", self.ptype, self.name),
        }
    }
}

pub fn parse(s: &str) -> Option<Purl> {
    let rest = s.strip_prefix("pkg:")?.trim_start_matches('/');
    let rest = rest.split('#').next()?;
    let rest = rest.split('?').next()?;
    let (ptype, path) = rest.split_once('/')?;

    // The version separator is the '@' after the last '/'. An npm scope's
    // '@' should be percent-encoded, but "pkg:npm/@babel/core" turns up in
    // real SBOMs too, and a plain rfind('@') would read "babel/core" as its
    // version.
    let last_slash = path.rfind('/');
    let (path, version) = match path.rfind('@') {
        Some(at) if last_slash.map_or(true, |slash| at > slash) => {
            (&path[..at], Some(decode(&path[at + 1..])?))
        }
        _ => (path, None),
    };

    let (namespace, name) = match path.rfind('/') {
        Some(i) => (Some(&path[..i]), &path[i + 1..]),
        None => (None, path),
    };
    if ptype.is_empty() || name.is_empty() {
        return None;
    }

    let ptype = ptype.to_ascii_lowercase();
    let mut name = decode(name)?;
    let mut namespace = match namespace {
        Some(ns) => Some(
            ns.split('/')
                .map(decode)
                .collect::<Option<Vec<_>>>()?
                .join("/"),
        ),
        None => None,
    };

    // Per-type normalisation the spec requires, so the same package
    // written two legal ways gets one identity.
    match ptype.as_str() {
        "npm" => {
            name = name.to_lowercase();
            namespace = namespace.map(|ns| ns.to_lowercase());
        }
        "pypi" => name = name.to_lowercase().replace('_', "-"),
        _ => {}
    }

    Some(Purl {
        ptype,
        namespace,
        name,
        version: version.filter(|v| !v.is_empty()),
    })
}

fn decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_npm_package() {
        let p = parse("pkg:npm/express@4.21.2").unwrap();
        assert_eq!(p.identity(), "npm/express");
        assert_eq!(p.version.as_deref(), Some("4.21.2"));
    }

    #[test]
    fn encoded_npm_scope() {
        let p = parse("pkg:npm/%40babel/core@7.24.0").unwrap();
        assert_eq!(p.identity(), "npm/@babel/core");
        assert_eq!(p.version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn unencoded_npm_scope_is_not_mistaken_for_a_version() {
        let p = parse("pkg:npm/@babel/core").unwrap();
        assert_eq!(p.identity(), "npm/@babel/core");
        assert_eq!(p.version, None);

        let p = parse("pkg:npm/@babel/core@7.24.0").unwrap();
        assert_eq!(p.identity(), "npm/@babel/core");
        assert_eq!(p.version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn qualifiers_and_subpath_do_not_change_identity() {
        let a = parse("pkg:maven/org.apache.commons/commons-text@1.10.0?type=jar#src").unwrap();
        let b = parse("pkg:maven/org.apache.commons/commons-text@1.11.0").unwrap();
        assert_eq!(a.identity(), b.identity());
        assert_eq!(a.identity(), "maven/org.apache.commons/commons-text");
    }

    #[test]
    fn pypi_names_normalise_case_and_underscores() {
        let a = parse("pkg:pypi/Django_Rest_Framework@3.15.0").unwrap();
        let b = parse("pkg:pypi/django-rest-framework@3.15.1").unwrap();
        assert_eq!(a.identity(), b.identity());
    }

    #[test]
    fn type_is_case_insensitive() {
        assert_eq!(
            parse("pkg:NPM/left-pad@1.3.0").unwrap().identity(),
            "npm/left-pad"
        );
    }

    #[test]
    fn go_module_paths_keep_their_slashes() {
        let p = parse("pkg:golang/github.com/sirupsen/logrus@v1.9.3").unwrap();
        assert_eq!(p.identity(), "golang/github.com/sirupsen/logrus");
        assert_eq!(p.version.as_deref(), Some("v1.9.3"));
    }

    #[test]
    fn rejects_what_is_not_a_purl() {
        assert_eq!(parse("npm/express@4.21.2"), None);
        assert_eq!(parse("pkg:npm/"), None);
        assert_eq!(parse("pkg:npm/bad%zzname@1.0.0"), None);
    }
}
