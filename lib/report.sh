#!/usr/bin/env bash
# lib/report.sh — Generate per-project markdown vulnerability reports

generate_report() {
    local name="$1"
    local json_file="$2"
    local output_file="$3"
    local repo_url="${4:-}"

    if [[ ! -f "$json_file" ]]; then
        echo "  WARNING: No scan results for $name, skipping report" >&2
        return 1
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

    local status
    if (( critical > 0 )); then
        status="FAIL (CRITICAL)"
    elif (( high > 0 )); then
        status="FAIL (HIGH)"
    elif (( medium > 0 || low > 0 || unknown > 0 )); then
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

        if (( total_vulns == 0 )); then
            echo "No vulnerabilities found."
            echo ""
        else
            echo "## Findings"
            echo ""
            # Group by target (file/package manager) then by library
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

            # Remediation commands
            echo "## Remediation"
            echo ""
            _generate_remediation "$json_file"
        fi
    } > "$output_file"
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
