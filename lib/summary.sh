#!/usr/bin/env bash
# lib/summary.sh — Generate portfolio-wide summary

generate_summary() {
    local scan_dir="$1"
    local output_file="$2"
    local config_json="${3:-}"
    local scan_date
    scan_date=$(date +%Y-%m-%d)

    local json_dir="$scan_dir/vulnerability-scans"
    local total_projects=0
    local pass_count=0
    local warn_count=0
    local fail_count=0

    local project_rows=""
    local critical_highlights=""
    local topdeps_file kev_file epss_file
    topdeps_file=$(mktemp)
    kev_file=$(mktemp)
    epss_file=$(mktemp)
    local incomplete_sboms=""
    local total_secrets=0
    local total_misconfigs=0

    local enrich_file="$scan_dir/enrichment.json"
    [[ -f "$enrich_file" ]] || enrich_file=""

    for json_file in "$json_dir"/*-trivy.json; do
        [[ -f "$json_file" ]] || continue
        total_projects=$((total_projects + 1))

        local name
        name=$(basename "$json_file" -trivy.json)

        local critical high medium low total
        critical=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file")
        high=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$json_file")
        medium=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$json_file")
        low=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$json_file")
        total=$(jq '[.Results[]? | .Vulnerabilities[]?] | length' "$json_file")

        local secrets misconfigs
        secrets=$(jq '[.Results[]? | .Secrets[]?] | length' "$json_file")
        misconfigs=$(jq '[.Results[]? | .Misconfigurations[]? | select(.Status != "PASS")] | length' "$json_file")
        total_secrets=$((total_secrets + secrets))
        total_misconfigs=$((total_misconfigs + misconfigs))

        local status emoji
        if (( critical > 0 || high > 0 || secrets > 0 )); then
            status="FAIL"; emoji="❌"; fail_count=$((fail_count + 1))
        elif (( medium > 0 || low > 0 || misconfigs > 0 )); then
            status="WARN"; emoji="⚠️"; warn_count=$((warn_count + 1))
        else
            status="PASS"; emoji="✅"; pass_count=$((pass_count + 1))
        fi

        # Collect exploitation intel rows (KEV + high-EPSS) for portfolio sections
        if [[ -n "$enrich_file" ]]; then
            jq -r --arg proj "$name" --slurpfile enr "$enrich_file" '
                .Results[]? | .Vulnerabilities[]? | ($enr[0][.VulnerabilityID] // {}) as $e |
                select($e.kev == true) |
                "\(.VulnerabilityID)\t\(.Severity)\t\(.PkgName)\t\($proj)\t\($e.kev_date_added // "—")\(if $e.kev_ransomware then " (ransomware)" else "" end)"
            ' "$json_file" 2>/dev/null | sort -u >> "$kev_file"
            jq -r --arg proj "$name" --slurpfile enr "$enrich_file" '
                .Results[]? | .Vulnerabilities[]? | ($enr[0][.VulnerabilityID] // {}) as $e |
                select($e.kev != true and ($e.epss // 0) >= 0.5 and (.Severity == "CRITICAL" or .Severity == "HIGH")) |
                "\(.VulnerabilityID)\t\($e.epss * 1000 | round / 10)\t\(.Severity)\t\(.PkgName)\t\($proj)"
            ' "$json_file" 2>/dev/null | sort -u >> "$epss_file"
        fi

        local sbom_flag=""
        if [[ -f "$scan_dir/SBOM/${name}.sbom-incomplete" ]]; then
            sbom_flag=" ⚠️🔍"
            incomplete_sboms+="- **$name**: SBOM was empty — lockfile missing or dependencies not detected. Vulnerability results may be incomplete.\n"
        fi


        # Link to the per-project vulnerability report
        local name_display="[$name](vulnerability-scans/${name}-vulnerability-report.md)"
        project_rows+="| $name_display | $emoji $status$sbom_flag | $critical | $high | $medium | $low | $total | $secrets | $misconfigs |\n"

        if (( critical > 0 )); then
            local crit_cves
            crit_cves=$(jq -r '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID] | unique | map("[\(.)](https://nvd.nist.gov/vuln/detail/\(.))") | join(", ")' "$json_file")
            critical_highlights+="- **$name**: $crit_cves\n"
        fi
        




        # Append vulnerable deps to temp file
        jq -r '
            [.Results[]? | .Vulnerabilities[]? | {pkg: .PkgName, sev: .Severity}] |
            if length == 0 then empty else
            group_by(.pkg) | .[] |
            {pkg: .[0].pkg, count: length, max_sev: (map(
                if .sev == "CRITICAL" then 0
                elif .sev == "HIGH" then 1
                elif .sev == "MEDIUM" then 2
                elif .sev == "LOW" then 3
                else 4 end
            ) | min | if . == 0 then "CRITICAL" elif . == 1 then "HIGH" elif . == 2 then "MEDIUM" elif . == 3 then "LOW" else "UNKNOWN" end)} |
            "\(.pkg)\t\(.count)\t\(.max_sev)"
            end
        ' "$json_file" >> "$topdeps_file"
    done

    # Aggregate compliance status from per-project JSONs
    local compliance_dir="$scan_dir/compliance"
    local compliance_status="none"
    local compliance_emoji=""
    local compliance_label=""
    if [[ -d "$compliance_dir" ]] && ls "$compliance_dir"/*-compliance-summary.json >/dev/null 2>&1; then
        local total_restricted total_unknown total_missing
        total_restricted=$(jq -s '[.[].restricted] | add // 0' "$compliance_dir"/*-compliance-summary.json)
        total_unknown=$(jq -s '[.[].unknown_license] | add // 0' "$compliance_dir"/*-compliance-summary.json)
        total_missing=$(jq -s '[.[].missing_license] | add // 0' "$compliance_dir"/*-compliance-summary.json)

        if (( total_restricted > 0 )); then
            compliance_status="action"
            compliance_emoji="❌"
            compliance_label="ACTION REQUIRED"
        elif (( total_unknown > 0 || total_missing > 0 )); then
            compliance_status="review"
            compliance_emoji="⚠️"
            compliance_label="REVIEW NEEDED"
        else
            compliance_status="compliant"
            compliance_emoji="✅"
            compliance_label="COMPLIANT"
        fi
    fi

    {
        echo "# Portfolio Vulnerability Summary"
        echo ""
        echo "**Scan Date:** $scan_date"
        echo "**Projects Scanned:** $total_projects"
        echo "**Scanner:** Trivy"
        echo ""
        echo "## Overview"
        echo ""
        echo "| Status | Count |"
        echo "|--------|-------|"
        echo "| ✅ PASS | $pass_count |"
        echo "| ⚠️ WARN | $warn_count |"
        echo "| ❌ FAIL | $fail_count |"
        if [[ -s "$kev_file" ]]; then
            local kev_unique
            kev_unique=$(cut -f1 "$kev_file" | sort -u | wc -l)
            echo "| 🔥 Actively Exploited CVEs | $kev_unique |"
        fi
        if (( total_secrets > 0 )); then
            echo "| 🔑 Secrets | $total_secrets |"
        fi
        if (( total_misconfigs > 0 )); then
            echo "| 🔧 Misconfigurations | $total_misconfigs |"
        fi
        if [[ "$compliance_status" != "none" ]]; then
            echo "| $compliance_emoji Compliance | $compliance_label |"
        fi
        echo ""

        # Exploitation intel first — this is the "3 that matter" section
        if [[ -s "$kev_file" ]]; then
            echo "## 🔥 Actively Exploited Vulnerabilities (CISA KEV)"
            echo ""
            echo "Confirmed exploited in the wild. **Patch these first.**"
            echo ""
            echo "| CVE | Severity | Package | Projects Affected | In KEV Since |"
            echo "|-----|----------|---------|-------------------|--------------|"
            awk -F'\t' '{
                key = $1 "\t" $2 "\t" $3 "\t" $5
                if (key in projects) projects[key] = projects[key] ", " $4
                else projects[key] = $4
            } END {
                for (key in projects) {
                    split(key, p, "\t")
                    printf "| [%s](https://nvd.nist.gov/vuln/detail/%s) | %s | %s | %s | %s |\n", p[1], p[1], p[2], p[3], projects[key], p[4]
                }
            }' "$kev_file" | sort
            echo ""
        fi

        if [[ -s "$epss_file" ]]; then
            echo "## ⚠️ High Exploitation Probability (EPSS ≥ 0.5)"
            echo ""
            echo "Critical/high CVEs with a ≥50% predicted chance of exploitation in the next 30 days."
            echo ""
            echo "| CVE | EPSS | Severity | Package | Projects Affected |"
            echo "|-----|------|----------|---------|-------------------|"
            awk -F'\t' '{
                key = $1 "\t" $2 "\t" $3 "\t" $4
                if (key in projects) projects[key] = projects[key] ", " $5
                else projects[key] = $5
            } END {
                for (key in projects) {
                    split(key, p, "\t")
                    printf "%s\t| [%s](https://nvd.nist.gov/vuln/detail/%s) | %s%% | %s | %s | %s |\n", p[2], p[1], p[1], p[2], p[3], p[4], projects[key]
                }
            }' "$epss_file" | sort -rn | cut -f2-
            echo ""
        fi

        echo "## Project Status"
        echo ""
        echo "| Project | Status | Critical | High | Medium | Low | Total | Secrets | Misconfig |"
        echo "|---------|--------|----------|------|--------|-----|-------|---------|-----------|"
        echo -e "$project_rows"

        if (( total_secrets > 0 )); then
            echo ""
            echo "## 🔑 Secrets Detected"
            echo ""
            echo "Leaked credentials found in $((total_secrets)) location(s). See the per-project"
            echo "reports for file and line numbers. **Rotate affected credentials** — they live"
            echo "on in git history even after removal."
        fi

        if [[ -n "$incomplete_sboms" ]]; then
            echo ""
            echo "## ⚠️ Incomplete SBOMs"
            echo ""
            echo "The following projects had empty SBOMs. This typically means lockfiles"
            echo "are not committed to the repo (e.g. package-lock.json in .gitignore)."
            echo "Vulnerability counts for these projects may be understated."
            echo ""
            echo -e "$incomplete_sboms"
        fi

        if [[ -n "$critical_highlights" ]]; then
            echo ""
            echo "## Critical Vulnerability Highlights"
            echo ""
            echo -e "$critical_highlights"
        fi

        if [[ -s "$topdeps_file" ]]; then
            echo ""
            echo "## Most Common Vulnerable Dependencies"
            echo ""
            echo "| Package | CVE Count | Max Severity |"
            echo "|---------|-----------|--------------|"
            awk -F'\t' '{
                counts[$1] += $2
                # Track max severity (lowest number = worst)
                split("CRITICAL HIGH MEDIUM LOW UNKNOWN", order, " ")
                for (i=1; i<=5; i++) rank[order[i]] = i
                if (!($1 in best) || rank[$3] < rank[best[$1]]) best[$1] = $3
            } END {
                for (pkg in counts) printf "%s\t%d\t%s\n", pkg, counts[pkg], best[pkg]
            }' "$topdeps_file" | sort -t$'\t' -k2 -rn | head -10 | while IFS=$'\t' read -r pkg count sev; do
                echo "| $pkg | $count | $sev |"
            done
        fi

        if [[ "$compliance_status" != "none" ]]; then
            echo ""
            echo "## Licensing Overview"
            echo ""
            echo "**Compliance Status:** $compliance_emoji $compliance_label"
            echo ""
            echo "For a full breakdown of license compliance across all scanned projects — including restricted, copyleft, unknown, and missing licenses — see the [Portfolio Compliance Summary](portfolio-compliance-summary.md)."
        fi
        echo ""
        echo "## Recommendations"
        echo ""
        if [[ -s "$kev_file" ]]; then
            echo "- **Immediate:** Patch the actively exploited (KEV) CVEs above — these are being exploited in the wild right now."
        fi
        if (( total_secrets > 0 )); then
            echo "- **Immediate:** Rotate the leaked credentials flagged in the secrets sections."
        fi
        if (( fail_count > 0 )); then
            echo "- Address CRITICAL and HIGH vulnerabilities in failing projects as a priority."
        fi
        if (( warn_count > 0 )); then
            echo "- Review MEDIUM/LOW vulnerabilities in warning projects for potential upgrades."
        fi
        if [[ -n "$incomplete_sboms" ]]; then
            echo "- Projects with incomplete SBOMs should commit lockfiles or add pre-scan dependency install steps."
        fi
        if (( pass_count == total_projects )); then
            echo "- All projects are clean. Continue monitoring for newly disclosed CVEs."
        fi
        echo "- Run \`vulnsweep\` regularly to catch newly disclosed vulnerabilities."
    } > "$output_file"

    rm -f "$topdeps_file" "$kev_file" "$epss_file"
}
