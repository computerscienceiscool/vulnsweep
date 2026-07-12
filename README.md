# vulnsweep

Portfolio vulnerability scanner powered by Trivy. Scans multiple Git repositories by URL, generates SBOMs, vulnerability reports, and a changelog showing what changed since the last scan.

Beyond CVEs, each scan also detects leaked secrets, IaC misconfigurations, and license issues, and enriches every CVE with exploitation intelligence — CISA KEV flags (confirmed exploited in the wild) and EPSS scores (predicted 30-day exploitation probability) — so reports answer "which of these actually matter" instead of just "how many are there."

Repos are scanned remotely by default. If a remote SBOM comes back empty (common when lockfiles aren't committed), vulnsweep falls back to a shallow clone with dependency install to get accurate results.

## Requirements

- [Trivy](https://trivy.dev/) v0.69+
- git
- jq
- python3 (with PyYAML)

## Quick Start

```bash
./vulnsweep portfolio-scanner.yaml
```

That's it. Results go to `./security-audit/<date>/`.

## Usage

```
vulnsweep [OPTIONS] <config-file>

Options:
  -h, --help       Show this help message
  -v, --verbose    Verbose output
```

## Configuration

All settings live in a YAML config file. See `portfolio-scanner.yaml` for a full example.

### Repos

List every repository to scan with a name and URL:

```yaml
repos:
  - name: my-project
    url: https://github.com/org/my-project

  - name: private-project
    url: https://gitea.example.com/org/private-project
```

Public repos work over HTTPS. Private repos need SSH key access on the machine running vulnsweep.

### Scanners

Choose which Trivy scanners run against each repo. All four are enabled by default:

```yaml
scanner:
  scanners:
    - vuln       # CVE scanning
    - secret     # leaked credentials, keys, tokens
    - misconfig  # Dockerfile/Terraform/K8s misconfigurations
    - license    # package license detection
```

### Output Formats

Toggle which outputs are generated:

```yaml
output:
  directory: ./security-audit
  formats:
    sbom: true              # CycloneDX JSON per project
    project_report: true    # Markdown vulnerability report per project
    portfolio_summary: true # Consolidated markdown summary
    changelog: true         # What changed since last scan
    compliance: true        # Per-project and portfolio compliance reports
    enrichment: true        # EPSS scores + CISA KEV flags per CVE
```

### Exploitation Intelligence (EPSS + KEV)

When `enrichment: true` (the default), every CVE is looked up against two free feeds:

- **CISA KEV** — the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), CVEs confirmed exploited in the wild
- **EPSS** — [FIRST.org's Exploit Prediction Scoring System](https://www.first.org/epss/), the predicted probability of exploitation in the next 30 days

This drives the triage sections in every report: KEV-listed CVEs are "patch immediately," HIGH/CRITICAL CVEs with EPSS ≥ 0.5 are "likely imminent," and everything else falls into normal patch cycles. The changelog also alerts when a CVE you were already carrying enters the KEV catalog.

Enrichment needs outbound network access to `cisa.gov` and `api.first.org`. If either feed is unreachable, the scan continues without that data.

### Compliance Policy

When `compliance: true` is set, vulnsweep checks each project's SBOM against a policy file. Place `compliance-policy.yaml` in the same directory as your config file. See `compliance-policy.yaml` for the full format.

### Git Integration

Automatically commit and push results to a remote repo:

```yaml
output:
  git:
    enabled: true
    remote: https://github.com/org/security-audit  # omit to commit locally only
```

When `enabled: true`, vulnsweep commits the scan results after each run. If `remote` is set, it pushes too. If not, results are committed locally and you push when you're ready.

## Output Structure

Each scan creates a date-stamped directory (MMDDYY format). If you run multiple times in a day, subsequent runs get a suffix (`-2`, `-3`, etc.).

```
security-audit/
├── 030226/                              # First scan on March 2, 2026
│   ├── SBOM/
│   │   ├── my-project-sbom.cdx.json     # CycloneDX SBOM
│   │   └── ...
│   ├── vulnerability-scans/
│   │   ├── my-project-trivy.json        # Raw Trivy JSON (used for diffing)
│   │   ├── my-project-vulnerability-report.md  # Human-readable report
│   │   └── ...
│   ├── compliance/
│   │   ├── my-project-compliance-report.md     # Per-project compliance report
│   │   ├── my-project-compliance-summary.json  # Machine-readable summary
│   ├── enrichment.json                  # EPSS scores + KEV flags per CVE
│   ├── portfolio-compliance-summary.md         # Portfolio-wide compliance
│   ├── portfolio-summary.md             # Status table across all projects
│   └── changelog.md                     # What changed since last scan
├── 030226-2/                            # Second scan same day
│   └── ...
└── latest -> 030226-2/                  # Symlink to most recent scan
```

### Output Files Explained

**Per-project SBOM** (`SBOM/<name>-sbom.cdx.json`)
CycloneDX JSON listing every dependency in the project. Generated by Trivy.

**Per-project Trivy JSON** (`vulnerability-scans/<name>-trivy.json`)
Raw scan output from Trivy. Machine-readable. Used internally by vulnsweep to generate the changelog and summary. You don't need to read this — it's the data behind the markdown report.

**Per-project vulnerability report** (`vulnerability-scans/<name>-vulnerability-report.md`)
Human-readable markdown report for one project. Contains:
- Severity summary (CRITICAL/HIGH/MEDIUM/LOW counts) plus secrets/misconfiguration/license counts
- Priority triage — actively exploited CVEs (CISA KEV) and likely-imminent ones (EPSS ≥ 0.5), when any exist
- Findings table with CVE ID, severity, EPSS score, KEV flag, package, installed version, fixed version
- Secrets found in the repo (file, line, rule) — rotate these, they live on in git history
- Misconfigurations (Dockerfile, Terraform, Kubernetes, etc.) with resolutions
- License findings outside the permissive/notice categories
- Remediation commands (`go get`, `npm install`, etc.)

**Enrichment data** (`enrichment.json`)
Machine-readable map of every CVE in the scan to its EPSS score/percentile and CISA KEV status. Used internally for the triage sections and the changelog's KEV alerts.

**Portfolio summary** (`portfolio-summary.md`)
Status table across all projects showing PASS/WARN/FAIL, vulnerability counts by severity, secrets and misconfiguration counts, critical highlights, and the most common vulnerable dependencies. Leads with the CVEs that matter most: an "actively exploited" (KEV) section and a "high exploitation probability" (EPSS ≥ 0.5) section.

**Per-project compliance report** (`compliance/<name>-compliance-report.md`)
Checks the project's SBOM against the compliance policy. Reports banned licenses, blocked packages, and required dependency violations.

**Portfolio compliance summary** (`portfolio-compliance-summary.md`)
Aggregated compliance status across all projects.

**Changelog** (`changelog.md`)
The most important output. Compares the current scan against the previous one and shows:
- **Entered CISA KEV** — CVEs you were already carrying that are now confirmed exploited in the wild. This is the alert that warrants a page.
- **New vulnerabilities** — CVEs that appeared since last scan (new disclosure or new dependency)
- **Fixed vulnerabilities** — CVEs that were remediated since last scan
- **Status changes** — projects that went from PASS to FAIL or vice versa
- **New/removed projects** — repos added or removed from the config

## Exit Codes

- `0` — No CRITICAL or HIGH vulnerabilities and no secrets found
- `1` — CRITICAL or HIGH vulnerabilities found, secrets detected, or scan errors

## Project Statuses

Each project gets a status based on its worst finding:

| Status | Meaning |
|--------|---------|
| PASS   | No findings |
| WARN   | Only MEDIUM or LOW vulnerabilities, or misconfigurations |
| FAIL   | CRITICAL or HIGH vulnerabilities, or secrets present |
