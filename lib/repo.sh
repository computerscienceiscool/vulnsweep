#!/usr/bin/env bash
# lib/repo.sh — Repo URL handling (no local cloning)

# Validate a repo URL is reachable (lightweight check)
check_repo_url() {
    local name="$1"
    local url="$2"

    # For HTTPS URLs, do a quick ls-remote
    if [[ "$url" == https://* ]]; then
        if ! git ls-remote --quiet "$url" HEAD >/dev/null 2>&1; then
            echo "  WARNING: Cannot reach $name at $url" >&2
            return 1
        fi
    fi
    # SSH URLs — skip check, trivy will fail if unreachable
    return 0
}
