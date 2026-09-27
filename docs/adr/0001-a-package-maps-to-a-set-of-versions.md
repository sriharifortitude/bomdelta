# ADR 1: a package maps to a set of versions, not one version

## Status
Accepted

## Context
The obvious data model for "what changed between two SBOMs" is a map from
package to version, then compare the two maps. The first real SBOM this
was written against (npm's own CycloneDX output for an express app, in
`testdata/`) has `ms` at 2.0.0 *and* 2.1.3, and `encodeurl` at 1.0.2 *and*
2.0.0. npm nests a second copy whenever two dependents need incompatible
ranges. Maven, Cargo and Go build lists do the same thing in other ways.

A name-to-version map keeps one of those copies and silently drops the
other. Nothing errors. The diff just stops seeing half of what's there.

## Decision
Identity is the purl without version, qualifiers or subpath (falling back
to group/name when there's no purl), and each identity maps to the *set*
of versions present. Comparison then works on sets:

- one version on each side: upgraded, downgraded, or "direction unknown";
- a version that appears next to a higher one that was already there:
  `older-copy-added`, medium;
- the highest version in the set going down: `downgraded`, high, even when
  that happens by a copy being removed rather than replaced.

## Consequences
- The `older-copy-added` rule exists because of this model, and it earned
  its place on the first real run. Downgrading express 4.21.2 to 4.20.0
  leaves `send` 0.19.0 in place and adds `send` 0.18.0 beside it. On
  2026-09-27, OSV.dev listed GHSA-m6fv-jmcg-4jfg (CVE-2024-43799) against
  0.18.0. A tool comparing only the highest version of each package would
  report `send` as unchanged.
- Two entries with the same identity *and* the same version count once.
  An SBOM that lists a package twice (both nested and flat) doesn't
  produce phantom additions.
- The cost is that a diff over sets is harder to explain in one line than
  "a -> b". Findings for multi-copy packages say what is still there
  ("0.18.0 added alongside newer 0.19.0"), not just what moved.
