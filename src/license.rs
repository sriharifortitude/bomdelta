//! Licence classification: coarse on purpose.
//!
//! This answers "did the obligations on this dependency get heavier?", not
//! "is this licence compatible with yours?" -- the second question needs
//! your own licence, your distribution model and usually a lawyer. The
//! categories are ordered by how much a change *into* them needs a human
//! to look at it, which is the only thing the diff uses them for.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Permissive,
    WeakCopyleft,
    /// Declared, but not an id this table knows -- a free-text name, a
    /// LicenseRef-, or a real SPDX id missing from the lists below. Ranked
    /// above weak copyleft: "we don't know" needs a person more than
    /// "file-level copyleft" does.
    Unrecognised,
    StrongCopyleft,
    /// Not open source: production use is restricted by the licence itself.
    SourceAvailable,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Permissive => "permissive",
            Category::WeakCopyleft => "weak copyleft",
            Category::Unrecognised => "unrecognised",
            Category::StrongCopyleft => "strong copyleft",
            Category::SourceAvailable => "source-available",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

const PERMISSIVE: &[&str] = &[
    "0BSD",
    "AFL-3.0",
    "APACHE-1.1",
    "APACHE-2.0",
    "ARTISTIC-2.0",
    "BLUEOAK-1.0.0",
    "BSD-1-CLAUSE",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "BSD-3-CLAUSE-CLEAR",
    "BSL-1.0",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "CC0-1.0",
    "CURL",
    "ISC",
    "MIT",
    "MIT-0",
    "NCSA",
    "OPENSSL",
    "POSTGRESQL",
    "PSF-2.0",
    "PYTHON-2.0",
    "UNICODE-3.0",
    "UNICODE-DFS-2016",
    "UNLICENSE",
    "UPL-1.0",
    "W3C",
    "WTFPL",
    "X11",
    "ZLIB",
];

// Matched as prefixes so every version and -only/-or-later variant lands
// in the same family: "GPL-" covers GPL-2.0, GPL-3.0-or-later, ... and
// never matches "LGPL-2.1" or "AGPL-3.0", which start differently.
const STRONG_COPYLEFT: &[&str] = &[
    "AGPL-",
    "CPAL-",
    "EUPL-",
    "GPL-",
    "OSL-",
    "RPL-",
    "SLEEPYCAT",
    "SSPL-",
];
const WEAK_COPYLEFT: &[&str] = &["CDDL-", "CPL-", "EPL-", "LGPL-", "MPL-", "MS-PL", "MS-RL"];
// BUSL is the Business Source License; BSL-1.0 above is Boost, which is
// permissive. The two are easy to confuse and mean opposite things.
const SOURCE_AVAILABLE: &[&str] = &["BUSL-", "ELASTIC-", "POLYFORM-"];

/// Exceptions that exist to let proprietary code link against the
/// library -- they turn "your whole program" copyleft into "changes to
/// this library" copyleft.
const LINKING_EXCEPTIONS: &[&str] = &[
    "CLASSPATH-EXCEPTION-2.0",
    "GCC-EXCEPTION-2.0",
    "GCC-EXCEPTION-3.1",
    "LLVM-EXCEPTION",
    "UNIVERSAL-FOSS-EXCEPTION-1.0",
];

pub fn classify_id(id: &str) -> Category {
    let id = id.trim().trim_end_matches('+').to_ascii_uppercase();
    if PERMISSIVE.contains(&id.as_str()) {
        Category::Permissive
    } else if SOURCE_AVAILABLE.iter().any(|p| id.starts_with(p)) {
        Category::SourceAvailable
    } else if STRONG_COPYLEFT.iter().any(|p| id.starts_with(p)) {
        Category::StrongCopyleft
    } else if WEAK_COPYLEFT.iter().any(|p| id.starts_with(p)) {
        Category::WeakCopyleft
    } else {
        Category::Unrecognised
    }
}

/// Evaluates an SPDX licence expression. `OR` is a choice the licensee
/// gets to make, so it takes the least restrictive side; `AND` means both
/// apply, so it takes the most restrictive. Anything that doesn't parse is
/// `Unrecognised`, never silently permissive.
pub fn classify_expression(expr: &str) -> Category {
    let tokens = tokenize(expr);
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    match parser.or_expr() {
        Some(cat) if parser.pos == tokens.len() => cat,
        _ => Category::Unrecognised,
    }
}

fn tokenize(expr: &str) -> Vec<String> {
    expr.replace('(', " ( ")
        .replace(')', " ) ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

struct Parser<'a> {
    tokens: &'a [String],
    pos: usize,
}

impl Parser<'_> {
    fn peek_keyword(&self, kw: &str) -> bool {
        // Operators are uppercase in the spec; lowercase "or" turns up in
        // real package metadata often enough to accept it.
        self.tokens
            .get(self.pos)
            .is_some_and(|t| t.eq_ignore_ascii_case(kw))
    }

    fn or_expr(&mut self) -> Option<Category> {
        let mut cat = self.and_expr()?;
        while self.peek_keyword("OR") {
            self.pos += 1;
            cat = cat.min(self.and_expr()?);
        }
        Some(cat)
    }

    fn and_expr(&mut self) -> Option<Category> {
        let mut cat = self.with_expr()?;
        while self.peek_keyword("AND") {
            self.pos += 1;
            cat = cat.max(self.with_expr()?);
        }
        Some(cat)
    }

    fn with_expr(&mut self) -> Option<Category> {
        let cat = self.atom()?;
        if self.peek_keyword("WITH") {
            self.pos += 1;
            let exception = self.tokens.get(self.pos)?.to_ascii_uppercase();
            self.pos += 1;
            if cat == Category::StrongCopyleft && LINKING_EXCEPTIONS.contains(&exception.as_str()) {
                return Some(Category::WeakCopyleft);
            }
        }
        Some(cat)
    }

    fn atom(&mut self) -> Option<Category> {
        let token = self.tokens.get(self.pos)?;
        self.pos += 1;
        match token.as_str() {
            "(" => {
                let cat = self.or_expr()?;
                if self.tokens.get(self.pos).map(String::as_str) != Some(")") {
                    return None;
                }
                self.pos += 1;
                Some(cat)
            }
            ")" => None,
            t if ["AND", "OR", "WITH"]
                .iter()
                .any(|kw| t.eq_ignore_ascii_case(kw)) =>
            {
                None
            }
            id => Some(classify_id(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Category::*;
    use super::*;

    #[test]
    fn common_ids_land_in_the_right_family() {
        assert_eq!(classify_id("MIT"), Permissive);
        assert_eq!(classify_id("Apache-2.0"), Permissive);
        assert_eq!(classify_id("GPL-2.0-or-later"), StrongCopyleft);
        assert_eq!(classify_id("GPL-3.0-only"), StrongCopyleft);
        assert_eq!(classify_id("AGPL-3.0-or-later"), StrongCopyleft);
        assert_eq!(classify_id("LGPL-2.1-only"), WeakCopyleft);
        assert_eq!(classify_id("MPL-2.0"), WeakCopyleft);
        assert_eq!(classify_id("BUSL-1.1"), SourceAvailable);
    }

    #[test]
    fn lgpl_is_not_caught_by_the_gpl_prefix() {
        assert_eq!(classify_id("LGPL-3.0-or-later"), WeakCopyleft);
    }

    #[test]
    fn boost_is_not_the_business_source_license() {
        assert_eq!(classify_id("BSL-1.0"), Permissive);
        assert_eq!(classify_id("BUSL-1.1"), SourceAvailable);
    }

    #[test]
    fn deprecated_plus_suffix_and_case_are_tolerated() {
        assert_eq!(classify_id("GPL-2.0+"), StrongCopyleft);
        assert_eq!(classify_id("mit"), Permissive);
    }

    #[test]
    fn unknown_ids_and_licenseref_are_unrecognised_not_permissive() {
        assert_eq!(classify_id("LicenseRef-Proprietary"), Unrecognised);
        assert_eq!(classify_id("SEE LICENSE IN LICENSE.md"), Unrecognised);
    }

    #[test]
    fn or_takes_the_choice_the_licensee_would_make() {
        assert_eq!(classify_expression("MIT OR GPL-3.0-only"), Permissive);
        assert_eq!(
            classify_expression("GPL-2.0-only OR LGPL-2.1-only"),
            WeakCopyleft
        );
    }

    #[test]
    fn and_takes_the_heavier_obligation() {
        assert_eq!(classify_expression("MIT AND GPL-3.0-only"), StrongCopyleft);
        assert_eq!(
            classify_expression("MIT AND LicenseRef-Custom"),
            Unrecognised
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // Reads as MIT OR (GPL AND Apache): the MIT option is still there.
        assert_eq!(
            classify_expression("MIT OR GPL-3.0-only AND Apache-2.0"),
            Permissive
        );
        // Parentheses override it.
        assert_eq!(
            classify_expression("(MIT OR GPL-3.0-only) AND Apache-2.0"),
            Permissive
        );
        assert_eq!(
            classify_expression("(MIT OR Apache-2.0) AND GPL-3.0-only"),
            StrongCopyleft
        );
    }

    #[test]
    fn linking_exception_softens_strong_copyleft() {
        assert_eq!(
            classify_expression("GPL-2.0-only WITH Classpath-exception-2.0"),
            WeakCopyleft
        );
        // An exception that isn't about linking changes nothing.
        assert_eq!(
            classify_expression("GPL-2.0-only WITH Autoconf-exception-2.0"),
            StrongCopyleft
        );
    }

    #[test]
    fn lowercase_operators_from_real_metadata_are_accepted() {
        assert_eq!(classify_expression("MIT or Apache-2.0"), Permissive);
    }

    #[test]
    fn malformed_expressions_are_unrecognised() {
        assert_eq!(classify_expression("(MIT OR"), Unrecognised);
        assert_eq!(classify_expression("MIT OR OR Apache-2.0"), Unrecognised);
        assert_eq!(classify_expression("MIT Apache-2.0"), Unrecognised);
        assert_eq!(classify_expression(""), Unrecognised);
    }
}
