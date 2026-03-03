#!/usr/bin/env bash
# lib/scan.sh — Run Trivy scans against remote repos (no cloning)

scan_repo() {
    local name="$1"
    local url="$2"
    local sbom_dir="$3"
    local scan_dir="$4"

    local sbom_file="$sbom_dir/${name}-sbom.cdx.json"
    local json_file="$scan_dir/${name}-trivy.json"
    local err_file
    err_file=$(mktemp)

    # For SSH URLs, verify connectivity before burning time on trivy
    if [[ "$url" == git@* ]]; then
        local host
        host=$(echo "$url" | sed 's/git@//;s/:.*//')
        if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" true 2>/dev/null; then
            echo "  ERROR: SSH connection to $host failed" >&2
            echo "  Check: ssh-agent running? Key added? Host reachable?" >&2
            rm -f "$err_file"
            return 1
        fi
    fi

    # Clear trivy's repo cache to ensure we scan the latest code
    trivy clean --scan-cache >/dev/null 2>&1

    # Generate SBOM (CycloneDX)
    echo "  Generating SBOM for $name..."
    if ! trivy repo --format cyclonedx --output "$sbom_file" "$url" 2>"$err_file"; then
        _report_scan_error "$name" "$url" "$err_file" "SBOM generation"
        # Non-fatal — continue to vuln scan
    fi

    # Vulnerability scan (JSON)
    echo "  Scanning $name for vulnerabilities..."
    if ! trivy repo --format json --output "$json_file" --scanners vuln "$url" 2>"$err_file"; then
        _report_scan_error "$name" "$url" "$err_file" "vulnerability scan"
        rm -f "$err_file"
        return 1
    fi

    rm -f "$err_file"
    return 0
}

_report_scan_error() {
    local name="$1"
    local url="$2"
    local err_file="$3"
    local phase="$4"

    local err_msg
    err_msg=$(cat "$err_file" 2>/dev/null)

    echo "  ERROR: $phase failed for $name" >&2

    if echo "$err_msg" | grep -qi "permission denied\|authentication\|publickey"; then
        echo "  Cause: SSH authentication failed" >&2
        echo "  Check: ssh-agent, key permissions, authorized_keys on server" >&2
    elif echo "$err_msg" | grep -qi "could not resolve\|no such host\|connection refused\|timeout"; then
        echo "  Cause: Cannot reach host" >&2
        echo "  Check: network connectivity, DNS, firewall" >&2
    elif echo "$err_msg" | grep -qi "not found\|404\|does not exist"; then
        echo "  Cause: Repository not found" >&2
        echo "  Check: URL spelling, repo visibility, access permissions" >&2
    else
        # Show the raw error for anything unexpected
        echo "  Detail: ${err_msg:0:200}" >&2
    fi
}
