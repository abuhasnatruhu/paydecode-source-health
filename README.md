# paydecode-source-health

Public runner for the official-source health check of paydecode.com. It contains one workflow and no
site content. Each run checks out the private source repository at an exact commit (read-only token in
the `PAYDECODE_SOURCE_TOKEN1` secret), verifies the checkout, runs that commit's own monitor, and
uploads the report with a provenance file that names the source commit, branch and this runner. The
source repository's release script validates that artifact before any deployment.

## Scheduled jobs

- `minimum-wage-freshness.yml`: daily 06:30 UTC on the head of the `PAYDECODE_SOURCE_REF` branch, plus dispatch with an exact SHA. Produces the trusted source receipt the release scripts require.
- `source-capture.yml`: Tuesday 05:00 UTC, captures every official source due within ten days and signs each receipt with `PAYDECODE_RECEIPT_SIGNING_KEY`; dispatch with explicit `name<TAB>url` lines for ad-hoc captures. Opens a pull request on the source repository when `PAYDECODE_SOURCE_WRITE_TOKEN` is set, otherwise uploads the receipts as an artifact.
- `quality.yml`: nightly 02:00 UTC full pre-deploy dry-run of the source repository.

Secrets: `PAYDECODE_SOURCE_TOKEN1` (read), `PAYDECODE_RECEIPT_SIGNING_KEY` (Ed25519 private key, PEM), optional `PAYDECODE_SOURCE_WRITE_TOKEN` (contents + pull requests write). Variable: `PAYDECODE_SOURCE_REF`.

## Fixed Burlingame City capture-only maintenance

`burlingame-city-capture-only.yml` is manual-only and accepts no URL, branch or
source-SHA input. It requests exactly
`https://burlingame.org/307/Minimum-Wage-Information` once, using the existing
identified maintenance client, a 20-second timeout and a 2 MiB body cap. It never
follows a redirect, retries, visits an archive or solves a challenge. Every new
attempt keeps its original body, headers, curl output and failure details;
existing attempt paths and symlinks are refused without deletion or replacement.

The workflow pins the source checkout, signer and verifier to the previously
reviewed `a013cf5e55985ece73d6720c1fc76ff9f9d18d72` commit. Its own tool is checked
out at the workflow's exact SHA. Only a complete eligible HTTP 200 capture reaches
the existing signer; the unchanged receipt-provenance gate then verifies it.
Failure artifacts are still uploaded under a unique run/attempt name with
overwrite disabled, and any failed capture/sign/verification/upload fails the
workflow. No dependency installation, new secret, write token, pull request,
source-review admission, deadline renewal, source-health clearance or deployment
is part of this workflow. Existing scheduled workflows are unchanged.

Local tests use a fake curl subprocess and never contact a publisher or sign:

```sh
node scripts/qa-burlingame-city-capture-only.mjs /absolute/path/to/local/paydecode-source-repository
```

Their fresh test directories are preserved beside the health checkout. Passing
these tests is not evidence that the remote workflow ran or that City content was
reviewed. A later capture needs its own artifact verification and separate
bounded source-review decision.
