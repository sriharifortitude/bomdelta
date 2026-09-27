# ADR 3: no waiver file

## Status
Accepted

## Context
Every scanner in this portfolio (tfwarden, credsweep, kubeshield, vulnlock,
apilint) has a waiver or allowlist file with a mandatory reason and, where
it makes sense, an expiry. Those tools scan a *state*: the same accepted
finding comes back on every run, so without a waiver it either blocks
every build forever or gets hidden by lowering the threshold for
everything.

bomdelta scans a *change*. Run on a pull request (base SBOM vs head SBOM),
a finding appears on exactly one run: the one where the change is
introduced. Once it's merged, the next pull request's base already
contains it and there's nothing to report.

## Decision
No waiver file. Accepting a finding means approving the pull request that
introduces it.

## Consequences
- There's no file of old exceptions to go stale, and no need for expiry
  dates to force them to be reviewed again.
- An intentional change (say, deliberately adopting a GPL component in a
  product that's already GPL) fails the check on that one pull request.
  The README describes the two ways to handle that: make the job
  non-blocking and post the Markdown report as a comment, or merge with an
  explicit override. Both leave a visible record of who accepted what.
- Running bomdelta against a fixed old baseline instead of the PR's base
  (for example, "everything since the last release") makes findings repeat
  on every run. That's a different use, and the README says to use
  `--fail-on none` for it rather than adding waivers after the fact.
