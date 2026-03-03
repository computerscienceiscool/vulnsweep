#!/usr/bin/env bash
# lib/config.sh — Parse YAML config file via python3

parse_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        echo "ERROR: Config file not found: $config_file" >&2
        return 1
    fi

    python3 -c "
import yaml, json, sys

with open('$config_file') as f:
    cfg = yaml.safe_load(f)

if not cfg:
    print('ERROR: Empty config file', file=sys.stderr)
    sys.exit(1)

if 'repos' not in cfg or not cfg['repos']:
    print('ERROR: No repos defined in config', file=sys.stderr)
    sys.exit(1)

# Output as JSON for easy consumption by jq
json.dump(cfg, sys.stdout)
"
}

get_output_dir() {
    local config_json="$1"
    echo "$config_json" | jq -r '.output.directory // "./security-audit"'
}

get_repo_count() {
    local config_json="$1"
    echo "$config_json" | jq '.repos | length'
}

get_repo_name() {
    local config_json="$1"
    local index="$2"
    echo "$config_json" | jq -r ".repos[$index].name"
}

get_repo_url() {
    local config_json="$1"
    local index="$2"
    echo "$config_json" | jq -r ".repos[$index].url"
}

get_format_flag() {
    local config_json="$1"
    local format="$2"
    echo "$config_json" | jq -r ".output.formats.$format // true"
}

get_git_enabled() {
    local config_json="$1"
    echo "$config_json" | jq -r '.output.git.enabled // false'
}

get_git_remote() {
    local config_json="$1"
    echo "$config_json" | jq -r '.output.git.remote // empty'
}
