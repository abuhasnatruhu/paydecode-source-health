# paydecode-source-health

Public runner for the official-source health check of paydecode.com. It contains one workflow and no
site content. Each run checks out the private source repository at an exact commit (read-only token in
the `PAYDECODE_SOURCE_TOKEN` secret), verifies the checkout, runs that commit's own monitor, and
uploads the report with a provenance file that names the source commit, branch and this runner. The
source repository's release script validates that artifact before any deployment.
