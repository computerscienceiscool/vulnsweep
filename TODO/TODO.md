# vulnsweep — Feature Tracker

## TODO

- 010 - Single-repo mode (build-time scanning)
- 011 - Cron job generation/setup helper
- 012 - Parallel repo scanning
- 013 - Notification support (email/webhook on new critical/high)
- 014 - Historical trend tracking (vuln counts over time)
- 015 - Configurable fail thresholds (severity, fix-available)
- 016 - Report template customization

## DONE

- 001 - Config file parsing (YAML repos, output settings, format flags)
- 002 - Repository clone/pull management (HTTPS + SSH)
- 003 - Trivy SBOM generation (CycloneDX JSON per project)
- 004 - Trivy vulnerability scanning (JSON per project)
- 005 - Per-project markdown vulnerability report generation
- 006 - Portfolio summary generation (consolidated markdown)
- 007 - Changelog generation (diff current vs previous scan)
- 008 - Output directory management (date-stamped dirs, latest symlink)
- 009 - Exit code handling (0 clean, 1 new critical/high)
