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
