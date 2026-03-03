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

        # Look up repo URL from config for linking
        local repo_url=""
        if [[ -n "$config_json" ]]; then
            repo_url=$(echo "$config_json" | jq -r --arg n "$name" '.repos[]? | select(.name == $n) | .url // empty')
        fi
        local name_display="$name"
        if [[ -n "$repo_url" ]]; then
            name_display="[$name]($repo_url)"
        fi

        project_rows+="| $name_display | $emoji $status | $critical | $high | $medium | $low | $total |\n"

        if (( critical > 0 )); then
            local crit_cves
            crit_cves=$(jq -r '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID] | unique | join(", ")' "$json_file")
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
            sort -t$'\t' -k2 -rn "$topdeps_file" | head -10 | while IFS=$'\t' read -r pkg count sev; do
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
        if (( pass_count == total_projects )); then
            echo "- All projects are clean. Continue monitoring for newly disclosed CVEs."
        fi
        echo "- Run \`vulnsweep\` regularly to catch newly disclosed vulnerabilities."
    } > "$output_file"

    rm -f "$topdeps_file"
}
