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


        # Check if SBOM has any components — if empty, fall back to local clone
    local component_count=0
    if [[ -f "$sbom_file" ]]; then
        component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null || echo 0)
    fi

    if (( component_count == 0 )); then
        echo "  SBOM empty — falling back to local clone + dependency install..."
        local clone_dir
        clone_dir=$(mktemp -d)

        if git clone --depth 1 --quiet "$url" "$clone_dir" 2>"$err_file"; then
            _install_dependencies "$clone_dir"

            echo "  Re-generating SBOM from local clone..."
            trivy fs --format cyclonedx --output "$sbom_file" "$clone_dir" 2>"$err_file" || true

            # Re-check — if still empty, flag it
            component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null || echo 0)
            if (( component_count == 0 )); then
                echo "  WARNING: SBOM still empty after dependency install" >&2
                touch "$sbom_dir/${name}.sbom-incomplete"
            fi

            echo "  Scanning $name for vulnerabilities (local)..."
            if ! trivy fs --format json --output "$json_file" --scanners vuln "$clone_dir" 2>"$err_file"; then
                _report_scan_error "$name" "$url" "$err_file" "vulnerability scan (local)"
                rm -rf "$clone_dir"
                rm -f "$err_file"
                return 1
            fi

            rm -rf "$clone_dir"
            rm -f "$err_file"
            return 0
        else
            _report_scan_error "$name" "$url" "$err_file" "git clone"
            rm -rf "$clone_dir"
            touch "$sbom_dir/${name}.sbom-incomplete"
        fi
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


# Detect and install dependencies for common package managers
_install_dependencies() {
    local dir="$1"

    # Node.js: generate lockfile where missing
    while IFS= read -r -d '' pkg_json; do
        local pkg_dir
        pkg_dir=$(dirname "$pkg_json")
        if [[ ! -f "$pkg_dir/package-lock.json" ]] && [[ ! -f "$pkg_dir/yarn.lock" ]]; then
            echo "    npm install in ${pkg_dir#$dir/}..."
            (cd "$pkg_dir" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund 2>/dev/null) || true
        fi
    done < <(find "$dir" -name 'package.json' -not -path '*/node_modules/*' -print0)

    # Go: download modules to populate go.sum if missing
    while IFS= read -r -d '' go_mod; do
        local go_dir
        go_dir=$(dirname "$go_mod")
        if [[ ! -f "$go_dir/go.sum" ]]; then
            echo "    go mod download in ${go_dir#$dir/}..."
            (cd "$go_dir" && go mod download 2>/dev/null) || true
        fi
    done < <(find "$dir" -name 'go.mod' -not -path '*/vendor/*' -print0)
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
