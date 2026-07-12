#!/usr/bin/env bash
# lib/report.sh — Generate per-project markdown vulnerability reports

generate_report() {
    local name="$1"
    local json_file="$2"
    local output_file="$3"
    local repo_url="${4:-}"
    local enrich_file="${5:-}"

    if [[ ! -f "$json_file" ]]; then
        echo "  WARNING: No scan results for $name, skipping report" >&2
        return 1
    fi

    # Normalize enrichment: always hand jq a valid CVE map (empty when disabled)
    local enrich_tmp
    enrich_tmp=$(mktemp)
    if [[ -n "$enrich_file" ]] && [[ -f "$enrich_file" ]]; then
        cp "$enrich_file" "$enrich_tmp"
        local has_enrichment=1
    else
        echo '{}' > "$enrich_tmp"
        local has_enrichment=0
    fi

    local scan_date
    scan_date=$(date +%Y-%m-%d)

    local total_vulns
    total_vulns=$(jq '[.Results[]? | .Vulnerabilities[]?] | length' "$json_file")

    local critical high medium low unknown
    critical=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file")
    high=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$json_file")
    medium=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$json_file")
    low=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$json_file")
    unknown=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "UNKNOWN")] | length' "$json_file")

    local secrets misconfigs license_flags
    secrets=$(jq '[.Results[]? | .Secrets[]?] | length' "$json_file")
    misconfigs=$(jq '[.Results[]? | .Misconfigurations[]? | select(.Status != "PASS")] | length' "$json_file")
    license_flags=$(jq '[.Results[]? | .Licenses[]? | select(.Category as $c | ["notice","permissive","unencumbered"] | index($c) | not)] | length' "$json_file")

    local kev_count epss_hot_count
    kev_count=$(jq --slurpfile enr "$enrich_tmp" '
        [.Results[]? | .Vulnerabilities[]? | select(($enr[0][.VulnerabilityID] // {}).kev == true) | .VulnerabilityID] | unique | length
    ' "$json_file")
    epss_hot_count=$(jq --slurpfile enr "$enrich_tmp" '
        [.Results[]? | .Vulnerabilities[]? | ($enr[0][.VulnerabilityID] // {}) as $e |
         select($e.kev != true and ($e.epss // 0) >= 0.5 and (.Severity == "CRITICAL" or .Severity == "HIGH")) |
         .VulnerabilityID] | unique | length
    ' "$json_file")

    local status
    if (( critical > 0 )); then
        status="FAIL (CRITICAL)"
    elif (( high > 0 )); then
        status="FAIL (HIGH)"
    elif (( secrets > 0 )); then
        status="FAIL (SECRETS)"
    elif (( medium > 0 || low > 0 || unknown > 0 || misconfigs > 0 )); then
        status="WARN"
    else
        status="PASS"
    fi

    {
        if [[ -n "$repo_url" ]]; then
            echo "# Vulnerability Report: [$name]($repo_url)"
        else
            echo "# Vulnerability Report: $name"
        fi
        echo ""
        echo "**Scan Date:** $scan_date"
        echo "**Scanner:** Trivy"
        echo "**Status:** $status"
        echo ""
        echo "## Summary"
        echo ""
        echo "| Severity | Count |"
        echo "|----------|-------|"
        echo "| CRITICAL | $critical |"
        echo "| HIGH | $high |"
        echo "| MEDIUM | $medium |"
        echo "| LOW | $low |"
        echo "| UNKNOWN | $unknown |"
        echo "| **Total** | **$total_vulns** |"
        echo ""
        if (( secrets > 0 || misconfigs > 0 || license_flags > 0 )); then
            echo "| Other Findings | Count |"
            echo "|----------------|-------|"
            (( secrets > 0 )) && echo "| 🔑 Secrets | $secrets |"
            (( misconfigs > 0 )) && echo "| 🔧 Misconfigurations | $misconfigs |"
            (( license_flags > 0 )) && echo "| ⚖️ License Findings | $license_flags |"
            echo ""
        fi

        # Priority triage: what to fix first, based on real-world exploitation data
        if (( has_enrichment )) && (( kev_count > 0 || epss_hot_count > 0 )); then
            echo "## Priority Triage"
            echo ""
            if (( kev_count > 0 )); then
                echo "### 🔥 Actively Exploited (CISA KEV) — patch immediately"
                echo ""
                echo "These CVEs are confirmed exploited in the wild per CISA's Known Exploited Vulnerabilities catalog."
                echo ""
                echo "| CVE | Severity | Package | Installed | Fixed | In KEV Since |"
                echo "|-----|----------|---------|-----------|-------|--------------|"
                jq -r --slurpfile enr "$enrich_tmp" '
                    [.Results[]? | .Vulnerabilities[]? | ($enr[0][.VulnerabilityID] // {}) as $e |
                     select($e.kev == true) | . + {kev_date: ($e.kev_date_added // "—"), rw: ($e.kev_ransomware // false)}
                    ] | unique_by(.VulnerabilityID + .PkgName)[] |
                    "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") | \(.kev_date)\(if .rw then " (ransomware)" else "" end) |"
                ' "$json_file"
                echo ""
            fi
            if (( epss_hot_count > 0 )); then
                echo "### ⚠️ Likely Imminent Exploitation (EPSS ≥ 0.5)"
                echo ""
                echo "High/critical CVEs with a ≥50% predicted probability of exploitation in the next 30 days (FIRST.org EPSS)."
                echo ""
                echo "| CVE | EPSS | Severity | Package | Installed | Fixed |"
                echo "|-----|------|----------|---------|-----------|-------|"
                jq -r --slurpfile enr "$enrich_tmp" '
                    [.Results[]? | .Vulnerabilities[]? | ($enr[0][.VulnerabilityID] // {}) as $e |
                     select($e.kev != true and ($e.epss // 0) >= 0.5 and (.Severity == "CRITICAL" or .Severity == "HIGH")) |
                     . + {epss: $e.epss}
                    ] | unique_by(.VulnerabilityID + .PkgName) | sort_by(-.epss)[] |
                    "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.epss * 1000 | round / 10)% | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") |"
                ' "$json_file"
                echo ""
            fi
        fi

        if (( total_vulns == 0 )); then
            echo "No vulnerabilities found."
            echo ""
        else
            echo "## Findings"
            echo ""
            # Group by target (file/package manager) then by library
            if (( has_enrichment )); then
                jq -r --slurpfile enr "$enrich_tmp" '
                    def pct: if . == null then "—" elif . < 0.001 then "<0.1%" else ((. * 1000 | round / 10 | tostring) + "%") end;
                    .Results[]? |
                    select(.Vulnerabilities != null and (.Vulnerabilities | length) > 0) |
                    .Target as $target |
                    .Type as $type |
                    "### Target: \($target) (\($type // "unknown"))\n",
                    "| CVE | Severity | EPSS | KEV | Package | Installed | Fixed | Title |",
                    "|-----|----------|------|-----|---------|-----------|-------|-------|",
                    (.Vulnerabilities | sort_by(
                        if .Severity == "CRITICAL" then 0
                        elif .Severity == "HIGH" then 1
                        elif .Severity == "MEDIUM" then 2
                        elif .Severity == "LOW" then 3
                        else 4 end
                    )[] | ($enr[0][.VulnerabilityID] // {}) as $e |
                        "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.Severity) | \($e.epss | pct) | \(if $e.kev == true then "🔥" else "" end) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") | \(.Title // "N/A" | gsub("[\\n\\r]"; " ") | if length > 60 then .[:60] + "..." else . end) |"
                    ),
                    ""
                ' "$json_file"
            else
                jq -r '
                    .Results[]? |
                    select(.Vulnerabilities != null and (.Vulnerabilities | length) > 0) |
                    .Target as $target |
                    .Type as $type |
                    "### Target: \($target) (\($type // "unknown"))\n",
                    "| CVE | Severity | Package | Installed | Fixed | Title |",
                    "|-----|----------|---------|-----------|-------|-------|",
                    (.Vulnerabilities | sort_by(
                        if .Severity == "CRITICAL" then 0
                        elif .Severity == "HIGH" then 1
                        elif .Severity == "MEDIUM" then 2
                        elif .Severity == "LOW" then 3
                        else 4 end
                    )[] |
                        "| [\(.VulnerabilityID)](https://nvd.nist.gov/vuln/detail/\(.VulnerabilityID)) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "N/A") | \(.Title // "N/A" | gsub("[\\n\\r]"; " ") | if length > 60 then .[:60] + "..." else . end) |"
                    ),
                    ""
                ' "$json_file"
            fi
        fi

        # Secrets (leaked credentials, keys, tokens)
        if (( secrets > 0 )); then
            echo "## 🔑 Secrets ($secrets)"
            echo ""
            echo "Potential credentials committed to the repository. **Rotate any real secrets"
            echo "immediately** — removing them from the current commit is not enough, they"
            echo "remain in git history."
            echo ""
            echo "| File | Line | Severity | Rule | Description |"
            echo "|------|------|----------|------|-------------|"
            jq -r '
                .Results[]? |
                select(.Secrets != null and (.Secrets | length) > 0) |
                .Target as $target |
                .Secrets[] |
                "| \($target) | \(.StartLine) | \(.Severity) | \(.RuleID) | \(.Title // "N/A") |"
            ' "$json_file"
            echo ""
        fi

        # Misconfigurations (Dockerfile, Terraform, K8s, etc.)
        if (( misconfigs > 0 )); then
            echo "## 🔧 Misconfigurations ($misconfigs)"
            echo ""
            echo "| ID | Severity | Target | Title | Resolution |"
            echo "|----|----------|--------|-------|------------|"
            jq -r '
                .Results[]? |
                select(.Misconfigurations != null and (.Misconfigurations | length) > 0) |
                .Target as $target |
                (.Misconfigurations[] | select(.Status != "PASS")) |
                "| [\(.ID)](\(.PrimaryURL // "#")) | \(.Severity) | \($target) | \(.Title // "N/A" | gsub("[\\n\\r|]"; " ")) | \(.Resolution // "N/A" | gsub("[\\n\\r|]"; " ") | if length > 80 then .[:80] + "..." else . end) |"
            ' "$json_file" | sort -t'|' -k3,3
            echo ""
        fi

        # License findings (non-permissive licenses flagged by trivy)
        if (( license_flags > 0 )); then
            echo "## ⚖️ License Findings ($license_flags)"
            echo ""
            echo "Licenses trivy classifies outside the permissive/notice categories."
            echo "Cross-check against the compliance policy (see the compliance report)."
            echo ""
            echo "| Package | License | Category | Severity | Source |"
            echo "|---------|---------|----------|----------|--------|"
            jq -r '
                [.Results[]? | .Target as $target | .Licenses[]? |
                 select(.Category as $c | ["notice","permissive","unencumbered"] | index($c) | not) |
                 "| \(.PkgName // "—") | \(.Name) | \(.Category) | \(.Severity) | \(if (.FilePath // "") == "" then $target else .FilePath end) |"
                ] | unique | .[]
            ' "$json_file"
            echo ""
        fi

        if (( total_vulns > 0 )); then
            # Remediation commands
            echo "## Remediation"
            echo ""
            _generate_remediation "$json_file"
        fi
    } > "$output_file"

    rm -f "$enrich_tmp"
}

_generate_remediation() {
    local json_file="$1"

    # Extract unique packages with fixes, grouped by type
    jq -r '
        [.Results[]? |
         .Type as $type |
         .Vulnerabilities[]? |
         select(.FixedVersion != null and .FixedVersion != "") |
         {type: $type, pkg: .PkgName, fixed: .FixedVersion}
        ] | unique_by(.pkg) | group_by(.type)[] |
        .[0].type as $type |
        if $type == "gomod" then
            "### Go modules\n\n```bash",
            (.[] | "go get \(.pkg)@v\(.fixed)"),
            "```\n"
        elif $type == "npm" or $type == "yarn" then
            "### Node.js\n\n```bash",
            (.[] | "npm install \(.pkg)@\(.fixed)"),
            "```\n"
        elif $type == "pip" or $type == "pipenv" or $type == "poetry" then
            "### Python\n\n```bash",
            (.[] | "pip install \(.pkg)>=\(.fixed)"),
            "```\n"
        else
            "### \($type)\n\nUpdate the following packages to their fixed versions:\n",
            (.[] | "- \(.pkg) -> \(.fixed)"),
            ""
        end
    ' "$json_file"
}
