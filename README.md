# trivy-kev-epss-action

[![CI](https://github.com/fogandfrog/trivy-kev-epss-action/actions/workflows/ci.yml/badge.svg)](https://github.com/fogandfrog/trivy-kev-epss-action/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Enrich a Trivy JSON report with the CISA Known Exploited Vulnerabilities (KEV) catalogue and FIRST EPSS scores, render a summary on the run page, and fail the workflow on exploitation evidence rather than on severity alone.

Trivy decides pass/fail on severity, and severity is a poor proxy for exploitation risk. CVEs on the KEV catalogue are regularly rated MEDIUM: CVE-2020-11023 (jQuery) and CVE-2026-48710 (Starlette) are both actively exploited and both MEDIUM, so a `--severity CRITICAL,HIGH` filter drops them before anything downstream can look at them. Many MEDIUM CVEs carry an EPSS score above 10 % while plenty of HIGHs sit near zero. This action is the missing step between Trivy and your merge button: it reads one Trivy JSON report (`fs`, `image`, `rootfs`, `repo` or `k8s`), joins every finding with KEV and EPSS, applies a configurable gate, writes a Markdown summary and annotations, emits an enriched JSON file with a stable schema, and exits non-zero when the gate fails. It is a composite action backed by a single standard-library Python script that also runs as a plain CLI.

## Quick start

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Trivy
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          scan-ref: .
          format: json
          output: trivy.json
          severity: CRITICAL,HIGH,MEDIUM
          exit-code: "0"
          version: v0.74.0

      - name: Gate on KEV and EPSS
        uses: fogandfrog/trivy-kev-epss-action@<sha> # v1.0.0
        with:
          report: trivy.json
```

`<sha>` is the full commit SHA of the release you want; see [Pin by commit SHA](#pin-by-commit-sha) for why the tag alone is not enough.

## What the summary looks like

The step summary (and stdout) for a container image scan:

> # ghcr.io/example/app:1.2.3
>
> **Gate: fail** — 1 of 2 findings fail the gate (KEV: 1, EPSS at or above 0.1: 1).
>
> Feeds: KEV catalogue 2026.09.04, 1695 entries · EPSS scores dated 2026-09-05. Source: ghcr.io/example/app:1.2.3 (container_image).
>
> ## Findings
>
> | Gate | ID | Severity | EPSS | KEV | Package | Installed | Fixed | Target |
> |---|---|---|---|---|---|---|---|---|
> | fail (kev, epss) | [CVE-2020-11023](https://avd.aquasec.com/nvd/cve-2020-11023) | MEDIUM | 0.8383 | yes (2025-01-23) | jquery | 3.4.1 | 3.5.0 | app/package-lock.json |
> | pass | [CVE-2025-20001](https://avd.aquasec.com/nvd/cve-2025-20001) | HIGH | 0.0020 | no | libexpat1 | 2.5.0-1+deb12u1 | unfixed | ghcr.io/example/app:1.2.3 (debian 12.7) |

Rows are sorted failing first, then KEV, then EPSS descending with `n/a` last, then severity. A `k8s` report adds a per-workload count table above the findings, and an ignore file that suppresses a KEV-listed ID adds a "Suppressed but known exploited" section at the top. Each failing finding also gets an `::error::` annotation (capped at ten plus a count) and each suppressed KEV ID a `::warning::`.

## Gate rules

| Condition | Fix available | Result |
|-----------|---------------|--------|
| On KEV | any | fail |
| EPSS at or above `epss-threshold` | any | fail |
| Severity in `fail-on-severity` | yes | fail |
| Severity in `fail-on-severity` | no | report only, unless `severity-gate-unfixed` |
| Non-CVE identifier (GHSA, PYSEC, …) | any | severity rule only, no KEV or EPSS lookup |
| Anything else | any | report only |

Findings are deduplicated on (ID, package, installed version, target) before counting. For `k8s` reports the workloads that share a finding are aggregated onto one row.

## Inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `report` | required | Path to the Trivy JSON report. |
| `trivyignore` | empty | Path to a `.trivyignore.yaml` or plain `.trivyignore`. Used only to warn about suppressed IDs that are on KEV; Trivy has already removed them from the report. |
| `epss-threshold` | `0.10` | EPSS score at or above which a finding fails the gate. |
| `fail-on-kev` | `true` | Fail on KEV membership, whether or not a fix exists. |
| `fail-on-epss` | `true` | Fail on EPSS at or above the threshold, whether or not a fix exists. |
| `fail-on-severity` | `CRITICAL,HIGH` | Severities that fail when a fix is available. Empty disables the severity rule. |
| `severity-gate-unfixed` | `false` | Apply `fail-on-severity` to unfixed findings as well. |
| `fail` | `true` | Exit non-zero when the gate fails. With `false` everything is still rendered and `outputs.gate` carries the verdict. |
| `title` | artifact name from the report | Heading of the summary. |
| `output` | `trivy-enriched.json` | Where the enriched JSON is written. |
| `step-summary` | `true` | Write the Markdown to `$GITHUB_STEP_SUMMARY`. |
| `max-rows` | `200` | Rows in the summary table. The full list is always in the JSON. |
| `kev-url` | CISA feed URL | Override for mirrors and tests. `file://` URLs are accepted. |
| `epss-url` | `https://api.first.org/data/v1/epss` | Same. |

## Outputs

| Output | Meaning |
|--------|---------|
| `gate` | `pass` or `fail`. |
| `failing` | Number of findings that failed the gate. |
| `total` | Number of findings after deduplication. |
| `kev` | Number of findings on KEV. |
| `epss-above-threshold` | Number of findings at or above the EPSS threshold. |
| `suppressed-kev` | Comma-separated IDs from the ignore file that are on KEV. |
| `report` | Path of the enriched JSON. |

The step exits `1` when the gate fails and `fail` is `true`, and `2` when the step itself cannot complete (unreadable report, empty KEV catalogue, EPSS feed that returns nothing for every queried CVE). Rendering always completes before a failing exit.

## Examples

### Container image

```yaml
      - name: Trivy
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: image
          image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
          format: json
          output: trivy.json
          severity: CRITICAL,HIGH,MEDIUM
          exit-code: "0"
          version: v0.74.0

      - name: Gate on KEV and EPSS
        id: gate
        uses: fogandfrog/trivy-kev-epss-action@<sha> # v1.0.0
        with:
          report: trivy.json
          trivyignore: .trivyignore.yaml
          epss-threshold: "0.05"

      - name: Keep the enriched report
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: trivy-enriched
          path: ${{ steps.gate.outputs.report }}
```

### Kubernetes cluster

```yaml
      - name: Trivy
        run: |
          trivy k8s --report all --format json --output trivy-k8s.json \
            --severity CRITICAL,HIGH,MEDIUM --exit-code 0 \
            --include-namespaces production

      - name: Gate on KEV and EPSS
        uses: fogandfrog/trivy-kev-epss-action@<sha> # v1.0.0
        with:
          report: trivy-k8s.json
          title: production cluster
          fail: "false"
```

With `fail: "false"` the verdict is still in `outputs.gate`, so a later step can decide what to do with it.

### As a plain CLI

```bash
python3 trivy_kev_epss.py --report trivy.json --epss-threshold 0.2 --output enriched.json
```

Every input has a matching `--flag`, and `INPUT_<NAME>` environment variables are read when a flag is absent. Outside GitHub Actions the Markdown goes to stdout and nothing else is written except the JSON.

## Trivy flags that make the gate meaningful

This action only sees what Trivy leaves in the report, so the scan must not pre-filter on the axis the gate replaces:

- `--severity CRITICAL,HIGH,MEDIUM` (or add `LOW`). Both reference KEV CVEs are MEDIUM; a `CRITICAL,HIGH` filter removes them before this action runs.
- No `--ignore-unfixed`. A finding without a fix that is exploited in the wild still fails the KEV and EPSS rules; the severity rule already leaves unfixed findings alone unless you opt in with `severity-gate-unfixed`.
- `--exit-code 0`. Let this action decide the verdict instead of Trivy.
- `--format json` with `--output <file>`, and pass that file as `report`.

## Enriched JSON

The JSON is a new document with a stable schema, not a patched Trivy report, so later tooling can collect it without caring which Trivy target produced it:

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-09-05T23:59:00Z",
  "source": {"artifactName": "ghcr.io/example/app:1.2.3", "artifactType": "container_image", "trivySchemaVersion": 2},
  "feeds": {"kev": {"dateReleased": "2026-09-04T16:47:03.5197Z", "catalogVersion": "2026.09.04", "count": 1695}, "epss": {"date": "2026-09-05"}},
  "policy": {"epssThreshold": 0.1, "failOnKev": true, "failOnEpss": true, "failOnSeverity": ["CRITICAL", "HIGH"], "severityGateUnfixed": false},
  "gate": {"result": "fail", "failing": 1, "total": 2, "kev": 1, "epssAboveThreshold": 1},
  "findings": [
    {
      "id": "CVE-2020-11023",
      "package": "jquery",
      "pkgPath": null,
      "installedVersion": "3.4.1",
      "fixedVersion": "3.5.0",
      "fixable": true,
      "severity": "MEDIUM",
      "status": "fixed",
      "targets": ["app/package-lock.json"],
      "workloads": [],
      "kev": {"listed": true, "dateAdded": "2025-01-23", "ransomware": "Unknown"},
      "epss": {"score": 0.8383, "percentile": 0.99681, "date": "2026-09-05"},
      "gate": {"fail": true, "reasons": ["kev", "epss"]},
      "title": "jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods",
      "url": "https://avd.aquasec.com/nvd/cve-2020-11023"
    }
  ],
  "suppressed": [{"id": "CVE-2021-44228", "kev": true, "statement": "JNDI lookup disabled at build time", "expiredAt": "2026-12-31"}]
}
```

`findings` is sorted like the summary table and is never truncated. `kev.listed`, `epss.score` and `gate.reasons` are the fields a downstream policy is most likely to read.

## Feeds

The action fetches the KEV catalogue from `cisa.gov` and EPSS scores from `api.first.org`, following redirects, with a 30 s timeout and three attempts with backoff. EPSS is queried only for identifiers matching `CVE-YYYY-NNNN+`, in batches of 100. An empty KEV catalogue, or an EPSS response that is empty for every batch, fails the step rather than silently passing everything: a broken feed must never look like a clean scan. A single CVE missing from EPSS (typically because it is too new) is rendered as `n/a` and is not a failure. No token or secret is needed, and the action works under `permissions: contents: read`.

If you mirror the feeds, note that `epss.cyentia.com` now 301-redirects to `epss.empiricalsecurity.com`, and a fetch that does not follow the redirect writes an empty file. This action follows redirects, but a mirror job built on `curl` without `-L` will produce an empty feed that this action then refuses.

## Pin by commit SHA

Reference this action, and every other third-party action, by its full commit SHA with the version in a trailing comment, as the examples above do. A tag is a moving pointer that anyone with write access to the repository can retarget. In March 2026, 76 of the 77 tags of Trivy's own GitHub Action were rewritten to point at credential-stealing code ([CVE-2026-33634](https://www.tenable.com/cve/CVE-2026-33634)); workflows pinned to `@v0.x` or `@master` picked it up on their next run, workflows pinned to a SHA did not. Dependabot understands SHA pins and keeps the version comment in sync when it proposes an update.

## Contributing

The implementation is one script, `trivy_kev_epss.py`, with the tests under `tests/`. Lint with `ruff check .` and `ruff format --check .`, run the tests with `pytest`; both run in CI on every pull request, and a weekly `live` job scans `tests/live/package-lock.json` (jQuery 3.4.1) with a real Trivy against the real feeds to catch feed format drift. Issues and pull requests are welcome.

## License

[MIT](LICENSE).
