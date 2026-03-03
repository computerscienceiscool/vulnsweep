#!/usr/bin/env bash
# lib/changelog.sh — Generate changelog by diffing current vs previous scan

generate_changelog() {
    local current_dir="$1"
    local previous_dir="$2"
    local output_file="$3"

    local scan_date
    scan_date=$(date +%Y-%m-%d)

    local prev_date
    prev_date=$(basename "$previous_dir")

    local cur_json_dir="$current_dir/vulnerability-scans"
    local prev_json_dir="$previous_dir/vulnerability-scans"

    # Build CVE sets: {cve}|{severity}|{package}|{project}
    local cur_cves prev_cves
    cur_cves=$(_collect_cves "$cur_json_dir")
    prev_cves=$(_collect_cves "$prev_json_dir")

    # New vulnerabilities: in current but not previous (by CVE+project)
    local new_vulns
    new_vulns=$(comm -23 \
        <(echo "$cur_cves" | sort -u) \
        <(echo "$prev_cves" | sort -u))

    # Fixed vulnerabilities: in previous but not current (by CVE+project)
    local fixed_vulns
    fixed_vulns=$(comm -13 \
        <(echo "$cur_cves" | sort -u) \
        <(echo "$prev_cves" | sort -u))

    # Collect project names from both scans
    local cur_projects prev_projects
    cur_projects=$(_list_projects "$cur_json_dir")
    prev_projects=$(_list_projects "$prev_json_dir")

    local new_projects removed_projects
    new_projects=$(comm -23 <(echo "$cur_projects" | sort) <(echo "$prev_projects" | sort))
    removed_projects=$(comm -13 <(echo "$cur_projects" | sort) <(echo "$prev_projects" | sort))

    # Status changes
    local status_changes=""
    while IFS= read -r project; do
        [[ -z "$project" ]] && continue
        local cur_status prev_status
        cur_status=$(_project_status "$cur_json_dir/${project}-trivy.json")
        prev_status=$(_project_status "$prev_json_dir/${project}-trivy.json")
        if [[ "$cur_status" != "$prev_status" ]]; then
            status_changes+="| $project | $prev_status | $cur_status |\n"
        fi
    done < <(comm -12 <(echo "$cur_projects" | sort) <(echo "$prev_projects" | sort))

    # Count unique new/fixed CVEs (deduplicated across projects)
    local new_cve_count fixed_cve_count
    new_cve_count=$(echo "$new_vulns" | grep -c '|' 2>/dev/null || echo 0)
    fixed_cve_count=$(echo "$fixed_vulns" | grep -c '|' 2>/dev/null || echo 0)

    {
        echo "# Vulnerability Scan Changelog — $scan_date"
        echo ""
        echo "Compared against previous scan: $prev_date"
        echo ""

        # New vulnerabilities
        echo "## New Vulnerabilities ($new_cve_count)"
        echo ""
        if [[ -n "$new_vulns" ]] && [[ "$new_cve_count" -gt 0 ]]; then
            echo "| CVE | Severity | Library | Projects Affected |"
            echo "|-----|----------|---------|-------------------|"
            # Group by CVE, aggregate projects
            echo "$new_vulns" | awk -F'|' '{
                key = $1 "|" $2 "|" $3
                if (key in projects) projects[key] = projects[key] ", " $4
                else projects[key] = $4
            } END {
                for (key in projects) {
                    split(key, parts, "|")
                    gsub(/ /, "", parts[1])
                    printf "| [%s](https://nvd.nist.gov/vuln/detail/%s) | %s | %s | %s |\n", parts[1], parts[1], parts[2], parts[3], projects[key]
                }
            }' | sort -t'|' -k3,3
            echo ""
        else
            echo "No new vulnerabilities found."
            echo ""
        fi

        # Fixed vulnerabilities
        echo "## Fixed Vulnerabilities ($fixed_cve_count)"
        echo ""
        if [[ -n "$fixed_vulns" ]] && [[ "$fixed_cve_count" -gt 0 ]]; then
            echo "| CVE | Severity | Library | Projects |"
            echo "|-----|----------|---------|----------|"
            echo "$fixed_vulns" | awk -F'|' '{
                key = $1 "|" $2 "|" $3
                if (key in projects) projects[key] = projects[key] ", " $4
                else projects[key] = $4
            } END {
                for (key in projects) {
                    split(key, parts, "|")
                    gsub(/ /, "", parts[1])
                    printf "| [%s](https://nvd.nist.gov/vuln/detail/%s) | %s | %s | %s |\n", parts[1], parts[1], parts[2], parts[3], projects[key]
                }
            }' | sort -t'|' -k3,3
            echo ""
        else
            echo "No vulnerabilities fixed since last scan."
            echo ""
        fi

        # Status changes
        echo "## Status Changes"
        echo ""
        if [[ -n "$status_changes" ]]; then
            echo "| Project | Previous | Current |"
            echo "|---------|----------|---------|"
            echo -e "$status_changes"
        else
            echo "No status changes."
            echo ""
        fi

        # New/removed projects
        if [[ -n "$new_projects" ]]; then
            echo "## New Projects"
            echo ""
            while IFS= read -r p; do
                [[ -n "$p" ]] && echo "- $p"
            done <<< "$new_projects"
            echo ""
        fi

        if [[ -n "$removed_projects" ]]; then
            echo "## Removed Projects"
            echo ""
            while IFS= read -r p; do
                [[ -n "$p" ]] && echo "- $p"
            done <<< "$removed_projects"
            echo ""
        fi

    } > "$output_file"
}

_collect_cves() {
    local json_dir="$1"
    for json_file in "$json_dir"/*-trivy.json; do
        [[ -f "$json_file" ]] || continue
        local project
        project=$(basename "$json_file" -trivy.json)
        jq -r --arg proj "$project" '
            [.Results[]? | .Vulnerabilities[]? |
             "\(.VulnerabilityID)|\(.Severity)|\(.PkgName)|\($proj)"]
            | .[]
        ' "$json_file" 2>/dev/null
    done
}

_list_projects() {
    local json_dir="$1"
    for json_file in "$json_dir"/*-trivy.json; do
        [[ -f "$json_file" ]] || continue
        basename "$json_file" -trivy.json
    done
}

_project_status() {
    local json_file="$1"
    if [[ ! -f "$json_file" ]]; then
        echo "N/A"
        return
    fi
    local critical high medium low
    critical=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file")
    high=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$json_file")
    medium=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$json_file")
    low=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$json_file")

    if (( critical > 0 )); then
        echo "❌ FAIL"
    elif (( high > 0 )); then
        echo "❌ FAIL"
    elif (( medium > 0 || low > 0 )); then
        echo "⚠️ WARN"
    else
        echo "✅ PASS"
    fi
}
