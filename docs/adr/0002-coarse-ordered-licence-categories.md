# ADR 2: licences are classified into a few ordered categories

## Status
Accepted

## Context
The licence question a release reviewer can actually answer from a diff is
"did the obligations on this dependency get heavier?". "Is this compatible
with our licence?" depends on the product's own licence, how it's
distributed and whether it's modified, and needs a person, often a lawyer.
A tool that pretends to answer the second question gives confident wrong
answers.

The real example in `testdata/` is TinyMCE. Version 6.8.5 is published as
MIT and 7.6.0 as GPL-2.0-or-later (checked against the npm registry on
2026-09-27). A routine major-version bump, the kind a dependency bot opens
every week, changes what shipping the product requires.

## Decision
Five categories, ordered by how much a change *into* them needs review:
permissive < weak copyleft < unrecognised < strong copyleft <
source-available. Classification is by SPDX id family (prefix match, so
every version and `-only`/`-or-later` variant of GPL lands together
without listing each one).

- **Expressions:** `OR` is a choice the licensee makes, so it takes the
  least restrictive side (`MIT OR GPL-3.0-only` is permissive). `AND`
  means both apply, so it takes the most restrictive. A linking exception
  (Classpath, GCC runtime, LLVM) moves strong copyleft to weak. Anything
  that doesn't parse is `unrecognised`.
- **Unrecognised ranks above weak copyleft.** "We don't know what this is"
  needs a person more than "file-level copyleft" does, and it must never
  quietly count as permissive.
- **No licence declared** is kept separate from "declared but
  unrecognised", and a new component with no licence is medium. The
  absence of a licence isn't permission to use.
- **Several entries in a component's `licenses` array are read as AND.**
  The CycloneDX schema doesn't say whether that list is a conjunction or a
  choice. Reading it as a choice could hide GPL behind MIT. Reading it as
  AND can at worst cause an unnecessary review.

## Consequences
- The table is short on purpose, and an SPDX id missing from it lands in
  `unrecognised` (medium), not permissive. Missing entries cost noise,
  never silence.
- `BSL-1.0` (Boost, permissive) and `BUSL-1.1` (Business Source License,
  not open source) sit one letter apart and mean opposite things. They
  have a dedicated test.
- A licence becoming *less* restrictive is still reported (low). It's a
  change someone may want to know about, not one that should fail a build.
