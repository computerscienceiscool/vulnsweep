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
    local topdeps_file
    topdeps_file=$(mktemp)
    local incomplete_sboms=""

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

        local status emoji
        if (( critical > 0 )); then
            status="FAIL"; emoji="❌"; fail_count=$((fail_count + 1))
        elif (( high > 0 )); then
            status="FAIL"; emoji="❌"; fail_count=$((fail_count + 1))
        elif (( medium > 0 || low > 0 )); then
            status="WARN"; emoji="⚠️"; warn_count=$((warn_count + 1))
        else
            status="PASS"; emoji="✅"; pass_count=$((pass_count + 1))
        fi

        local sbom_flag=""
        if [[ -f "$scan_dir/SBOM/${name}.sbom-incomplete" ]]; then
            sbom_flag=" ⚠️🔍"
            incomplete_sboms+="- **$name**: SBOM was empty — lockfile missing or dependencies not detected. Vulnerability results may be incomplete.\n"
        fi


        # Link to the per-project vulnerability report
        local name_display="[$name](vulnerability-scans/${name}-vulnerability-report.md)"
        project_rows+="| $name_display | $emoji $status$sbom_flag | $critical | $high | $medium | $low | $total |\n"

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
        echo ""
        echo "## Project Status"
        echo ""
        echo "| Project | Status | Critical | High | Medium | Low | Total |"
        echo "|---------|--------|----------|------|--------|-----|-------|"
        echo -e "$project_rows"

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

        echo ""
        echo "## Recommendations"
        echo ""
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

    rm -f "$topdeps_file"
}
