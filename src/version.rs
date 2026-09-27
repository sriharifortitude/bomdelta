//! Version ordering across ecosystems, with an explicit "can't tell".
//!
//! npm, Cargo, Go and most PyPI releases agree on dotted numeric segments
//! and a semver-style pre-release suffix. Maven qualifiers ("1.0.Final"),
//! Debian epochs ("1:2.3") and calendar-ish schemes don't, and a comparator
//! that falls back to string order for those would report "2.10" as older
//! than "2.9" in some other shape. So anything this can't order with
//! confidence comes back as `None`, and the diff reports the change as
//! "version order unknown" instead of guessing a direction.

use std::cmp::Ordering;

pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    if a == b {
        return Some(Ordering::Equal);
    }
    let (a_main, a_pre) = split(a);
    let (b_main, b_pre) = split(b);

    match compare_main(&a_main, &b_main)? {
        Ordering::Equal => {}
        other => return Some(other),
    }
    match (a_pre, b_pre) {
        (None, None) => Some(Ordering::Equal),
        // 1.0.0-rc.1 comes before 1.0.0
        (Some(_), None) => Some(Ordering::Less),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(x), Some(y)) => Some(compare_prerelease(x, y)),
    }
}

fn split(v: &str) -> (Vec<&str>, Option<&str>) {
    let v = v
        .strip_prefix('v')
        .or_else(|| v.strip_prefix('V'))
        .unwrap_or(v);
    let v = v.split('+').next().unwrap_or(v); // build metadata never affects order
    match v.split_once('-') {
        Some((main, pre)) => (main.split('.').collect(), Some(pre)),
        None => (v.split('.').collect(), None),
    }
}

fn compare_main(a: &[&str], b: &[&str]) -> Option<Ordering> {
    for i in 0..a.len().max(b.len()) {
        // 1.2 and 1.2.0 are the same release
        let x = a.get(i).copied().unwrap_or("0");
        let y = b.get(i).copied().unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(p), Ok(q)) => p.cmp(&q),
            _ if x == y => Ordering::Equal,
            _ => return None,
        };
        if ord != Ordering::Equal {
            return Some(ord);
        }
    }
    Some(Ordering::Equal)
}

/// Semver 2.0.0 section 11: identifiers compared left to right, numeric
/// ones numerically and below any alphanumeric one, and a shorter list
/// sorts first when every shared identifier is equal.
fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut xs = a.split('.');
    let mut ys = b.split('.');
    loop {
        match (xs.next(), ys.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(p), Ok(q)) => p.cmp(&q),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn numeric_segments_compare_as_numbers_not_strings() {
        assert_eq!(compare("2.10.0", "2.9.0"), Some(Greater));
        assert_eq!(compare("4.20.0", "4.21.2"), Some(Less));
    }

    #[test]
    fn missing_trailing_segments_are_zero() {
        assert_eq!(compare("1.2", "1.2.0"), Some(Equal));
        assert_eq!(compare("1.2", "1.2.1"), Some(Less));
    }

    #[test]
    fn leading_v_and_build_metadata_are_ignored() {
        assert_eq!(compare("v1.9.3", "1.9.3"), Some(Equal));
        assert_eq!(compare("1.0.0+build.5", "1.0.0+build.9"), Some(Equal));
    }

    #[test]
    fn prerelease_sorts_before_its_release() {
        assert_eq!(compare("1.0.0-rc.1", "1.0.0"), Some(Less));
        assert_eq!(compare("1.0.0", "1.0.0-rc.1"), Some(Greater));
    }

    #[test]
    fn prerelease_ordering_follows_the_semver_example_chain() {
        // The exact precedence chain given in semver 2.0.0 section 11.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in chain.windows(2) {
            assert_eq!(
                compare(pair[0], pair[1]),
                Some(Less),
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn go_pseudo_versions_order_by_timestamp() {
        assert_eq!(
            compare(
                "v0.0.0-20240101000000-abcdef123456",
                "v0.0.0-20240301000000-0123456789ab"
            ),
            Some(Less)
        );
    }

    #[test]
    fn refuses_to_guess_when_segments_are_not_numeric() {
        assert_eq!(compare("1.0.Final", "1.0.1"), None);
        assert_eq!(compare("1:2.3", "2.3"), None);
    }

    #[test]
    fn identical_non_numeric_versions_are_still_equal() {
        assert_eq!(compare("1.0.Final", "1.0.Final"), Some(Equal));
    }
}
