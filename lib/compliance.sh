#!/usr/bin/env bash
# lib/compliance.sh — License and export control compliance checks
# Reads CycloneDX SBOMs and checks components against a policy file.

# Run compliance checks for a single project
check_project_compliance() {
    local name="$1"
    local sbom_file="$2"
    local policy_file="$3"
    local output_file="$4"

    if [[ ! -f "$sbom_file" ]]; then
        echo "  WARNING: No SBOM for $name, skipping compliance check" >&2
        return 1
    fi

    if [[ ! -f "$policy_file" ]]; then
        echo "  WARNING: No compliance policy file found, skipping compliance check" >&2
        return 1
    fi

    local component_count
    component_count=$(jq '.components | length' "$sbom_file" 2>/dev/null || echo 0)

    if (( component_count == 0 )); then
        echo "  WARNING: SBOM empty for $name, skipping compliance check" >&2
        return 1
    fi

    # Run the python compliance checker
    python3 - "$sbom_file" "$policy_file" "$output_file" "$name" << 'PYEOF'
import json, yaml, sys, re

sbom_file = sys.argv[1]
policy_file = sys.argv[2]
output_file = sys.argv[3]
project_name = sys.argv[4]

with open(sbom_file) as f:
    sbom = json.load(f)

with open(policy_file) as f:
    policy = yaml.safe_load(f)

components = sbom.get("components", [])

# Build policy sets
approved_licenses = set(policy.get("licenses", {}).get("approved", []))
restricted_licenses = set(policy.get("licenses", {}).get("restricted", []))
copyleft_licenses = set(policy.get("licenses", {}).get("copyleft_warning", []))

export_patterns = [p.lower() for p in policy.get("export_control", {}).get("name_patterns", [])]
export_known = set(policy.get("export_control", {}).get("known_packages", []))

use_restrictions = {r["name"]: r for r in policy.get("use_restrictions", []) if isinstance(r, dict)}

# Results
license_ok = []
license_restricted = []
license_copyleft = []
license_unknown = []
license_missing = []
export_flagged = []
use_flagged = []

for comp in components:
    comp_name = comp.get("name", "unknown")
    comp_group = comp.get("group", "")
    comp_version = comp.get("version", "N/A")
    comp_type = comp.get("type", "")

    # Skip the top-level application entry (package-lock.json reference)
    if comp_type == "application":
        continue

    # Build full package name
    if comp_group:
        if comp_group.startswith("@"):
            full_name = f"{comp_group}/{comp_name}"
        else:
            full_name = f"@{comp_group}/{comp_name}"
    else:
        full_name = comp_name

    display = f"{full_name}@{comp_version}" if comp_version != "N/A" else full_name

    # --- License check ---
    licenses_found = []
    license_entries = comp.get("licenses", [])
    for lic_entry in license_entries:
        lic = lic_entry.get("license", {})
        lic_id = lic.get("id", "")
        lic_name = lic.get("name", "")
        if lic_id:
            licenses_found.append(lic_id)
        elif lic_name:
            licenses_found.append(lic_name)

    if not licenses_found:
        license_missing.append({"name": display, "full_name": full_name})
    else:
        for lic in licenses_found:
            if lic in restricted_licenses:
                license_restricted.append({"name": display, "license": lic, "full_name": full_name})
            elif lic in copyleft_licenses:
                license_copyleft.append({"name": display, "license": lic, "full_name": full_name})
            elif lic in approved_licenses:
                license_ok.append({"name": display, "license": lic, "full_name": full_name})
            else:
                license_unknown.append({"name": display, "license": lic, "full_name": full_name})

    # --- Export control check ---
    name_lower = full_name.lower()
    flagged = False

    # Check known packages list
    if full_name in export_known:
        flagged = True

    # Check name patterns
    if not flagged:
        for pattern in export_patterns:
            if pattern in name_lower:
                flagged = True
                break

    if flagged:
        export_flagged.append({"name": display, "full_name": full_name,
                               "licenses": ", ".join(licenses_found) if licenses_found else "N/A"})

    # --- Use restrictions check ---
    if full_name in use_restrictions:
        entry = use_restrictions[full_name]
        use_flagged.append({
            "name": display,
            "restriction": entry.get("restriction", "See policy"),
            "status": entry.get("status", "unknown"),
            "reviewer": entry.get("reviewer", "N/A"),
            "date": entry.get("date", "N/A"),
        })

# --- Generate report ---
lines = []
lines.append(f"# Compliance Report: {project_name}")
lines.append("")
lines.append(f"**Components Analyzed:** {len([c for c in components if c.get('type') != 'application'])}")
lines.append("")

# Summary counts
total_issues = len(license_restricted) + len(license_unknown) + len(license_missing) + len(export_flagged) + len(use_flagged)
lines.append("## Summary")
lines.append("")
lines.append("| Check | Count | Status |")
lines.append("|-------|-------|--------|")

def status_emoji(count, level="error"):
    if count == 0:
        return "✅ PASS"
    if level == "warn":
        return "⚠️ REVIEW"
    return "❌ ACTION"

lines.append(f"| Approved Licenses | {len(license_ok)} | ✅ |")
lines.append(f"| Restricted Licenses | {len(license_restricted)} | {status_emoji(len(license_restricted))} |")
lines.append(f"| Copyleft Licenses | {len(license_copyleft)} | {status_emoji(len(license_copyleft), 'warn')} |")
lines.append(f"| Unknown Licenses | {len(license_unknown)} | {status_emoji(len(license_unknown), 'warn')} |")
lines.append(f"| Missing Licenses | {len(license_missing)} | {status_emoji(len(license_missing), 'warn')} |")
lines.append(f"| Export Control Flags | {len(export_flagged)} | {status_emoji(len(export_flagged), 'warn')} |")
lines.append(f"| Use Restrictions | {len(use_flagged)} | {status_emoji(len(use_flagged))} |")
lines.append("")

# Restricted licenses
if license_restricted:
    lines.append("## ❌ Restricted Licenses")
    lines.append("")
    lines.append("These packages use licenses that may be incompatible with your project")
    lines.append("or prohibited for government use. **Action required.**")
    lines.append("")
    lines.append("| Package | License |")
    lines.append("|---------|---------|")
    for item in sorted(license_restricted, key=lambda x: x["name"]):
        lines.append(f"| {item['name']} | {item['license']} |")
    lines.append("")

# Copyleft warnings
if license_copyleft:
    lines.append("## ⚠️ Copyleft Licenses")
    lines.append("")
    lines.append("These packages use copyleft licenses. Review how they are linked/used")
    lines.append("to determine if your project must also be open-sourced.")
    lines.append("")
    lines.append("| Package | License |")
    lines.append("|---------|---------|")
    for item in sorted(license_copyleft, key=lambda x: x["name"]):
        lines.append(f"| {item['name']} | {item['license']} |")
    lines.append("")

# Unknown licenses
if license_unknown:
    lines.append("## ⚠️ Unknown Licenses")
    lines.append("")
    lines.append("These licenses are not in the approved or restricted lists.")
    lines.append("Add them to your compliance policy after review.")
    lines.append("")
    lines.append("| Package | License |")
    lines.append("|---------|---------|")
    for item in sorted(license_unknown, key=lambda x: x["name"]):
        lines.append(f"| {item['name']} | {item['license']} |")
    lines.append("")

# Missing licenses
if license_missing:
    lines.append("## ⚠️ Missing License Information")
    lines.append("")
    lines.append("No license information found in the SBOM for these packages.")
    lines.append("Verify manually before use in regulated environments.")
    lines.append("")
    lines.append("| Package |")
    lines.append("|---------|")
    for item in sorted(license_missing, key=lambda x: x["name"]):
        lines.append(f"| {item['name']} |")
    lines.append("")

# Export control
if export_flagged:
    lines.append("## 🔒 Export Control — Cryptography Packages")
    lines.append("")
    lines.append("The following packages likely involve cryptographic functionality.")
    lines.append("Under US EAR (Export Administration Regulations), products using")
    lines.append("encryption may require BIS classification. This is not a legal")
    lines.append("determination — consult your export compliance team.")
    lines.append("")
    lines.append("| Package | License |")
    lines.append("|---------|---------|")
    for item in sorted(export_flagged, key=lambda x: x["name"]):
        lines.append(f"| {item['name']} | {item['licenses']} |")
    lines.append("")

# Use restrictions
if use_flagged:
    lines.append("## 🚫 Use Restrictions")
    lines.append("")
    lines.append("These packages have known use restrictions per your team's policy.")
    lines.append("")
    lines.append("| Package | Restriction | Status | Reviewer | Date |")
    lines.append("|---------|-------------|--------|----------|------|")
    for item in use_flagged:
        lines.append(f"| {item['name']} | {item['restriction']} | {item['status']} | {item['reviewer']} | {item['date']} |")
    lines.append("")

# Approved (collapsed)
lines.append("## ✅ Approved Licenses")
lines.append("")
lines.append(f"{len(license_ok)} packages with approved licenses.")
lines.append("")
if license_ok:
    # Group by license
    by_license = {}
    for item in license_ok:
        lic = item["license"]
        if lic not in by_license:
            by_license[lic] = []
        by_license[lic].append(item["name"])

    lines.append("| License | Count | Packages |")
    lines.append("|---------|-------|----------|")
    for lic in sorted(by_license.keys()):
        pkgs = by_license[lic]
        # Truncate long lists
        if len(pkgs) > 5:
            display_pkgs = ", ".join(pkgs[:5]) + f", +{len(pkgs)-5} more"
        else:
            display_pkgs = ", ".join(pkgs)
        lines.append(f"| {lic} | {len(pkgs)} | {display_pkgs} |")
    lines.append("")

with open(output_file, "w") as f:
    f.write("\n".join(lines))

# Output summary JSON to stdout for portfolio rollup
summary = {
    "project": project_name,
    "total_components": len([c for c in components if c.get("type") != "application"]),
    "approved": len(license_ok),
    "restricted": len(license_restricted),
    "copyleft": len(license_copyleft),
    "unknown_license": len(license_unknown),
    "missing_license": len(license_missing),
    "export_flagged": len(export_flagged),
    "use_restricted": len(use_flagged),
    "restricted_details": [{"name": i["name"], "license": i["license"]} for i in license_restricted],
    "export_details": [{"name": i["name"]} for i in export_flagged],
}

print(json.dumps(summary))
PYEOF
}

# Generate portfolio-wide compliance summary
generate_compliance_summary() {
    local scan_dir="$1"
    local output_file="$2"
    local compliance_dir="$scan_dir/compliance"

    local scan_date
    scan_date=$(date +%Y-%m-%d)

    # Collect all per-project compliance JSON summaries
    local all_summaries="$compliance_dir/.summaries.json"

    # Build JSON array from individual summary files
    echo "[" > "$all_summaries"
    local first=true
    for summary_file in "$compliance_dir"/*-compliance-summary.json; do
        [[ -f "$summary_file" ]] || continue
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$all_summaries"
        fi
        cat "$summary_file" >> "$all_summaries"
    done
    echo "]" >> "$all_summaries"

    python3 - "$all_summaries" "$output_file" "$scan_date" << 'PYEOF'
import json, sys

summaries_file = sys.argv[1]
output_file = sys.argv[2]
scan_date = sys.argv[3]

with open(summaries_file) as f:
    projects = json.load(f)

if not projects:
    with open(output_file, "w") as f:
        f.write("# Portfolio Compliance Summary\n\nNo projects with SBOM data.\n")
    sys.exit(0)

total_projects = len(projects)
total_components = sum(p["total_components"] for p in projects)
total_approved = sum(p["approved"] for p in projects)
total_restricted = sum(p["restricted"] for p in projects)
total_copyleft = sum(p["copyleft"] for p in projects)
total_unknown = sum(p["unknown_license"] for p in projects)
total_missing = sum(p["missing_license"] for p in projects)
total_export = sum(p["export_flagged"] for p in projects)
total_use = sum(p["use_restricted"] for p in projects)

lines = []
lines.append("# Portfolio Compliance Summary")
lines.append("")
lines.append(f"**Scan Date:** {scan_date}")
lines.append(f"**Projects Analyzed:** {total_projects}")
lines.append(f"**Total Components:** {total_components}")
lines.append("")

# Overall status
has_restricted = total_restricted > 0
has_issues = has_restricted or total_unknown > 0 or total_missing > 0

if has_restricted:
    overall = "❌ ACTION REQUIRED — restricted licenses found"
elif has_issues:
    overall = "⚠️ REVIEW NEEDED — unknown or missing licenses"
else:
    overall = "✅ COMPLIANT — all licenses approved"

lines.append(f"**Overall Status:** {overall}")
lines.append("")

# Overview table
lines.append("## Overview")
lines.append("")
lines.append("| Check | Count |")
lines.append("|-------|-------|")
lines.append(f"| Approved Licenses | {total_approved} |")
lines.append(f"| Restricted Licenses | {total_restricted} |")
lines.append(f"| Copyleft Licenses | {total_copyleft} |")
lines.append(f"| Unknown Licenses | {total_unknown} |")
lines.append(f"| Missing Licenses | {total_missing} |")
lines.append(f"| Export Control Flags | {total_export} |")
lines.append(f"| Use Restrictions | {total_use} |")
lines.append("")

# Per-project status table
lines.append("## Project Status")
lines.append("")
lines.append("| Project | Components | Approved | Restricted | Copyleft | Unknown | Missing | Export | Status |")
lines.append("|---------|-----------|----------|------------|----------|---------|---------|--------|--------|")

for p in sorted(projects, key=lambda x: x["project"]):
    name = p["project"]
    report_link = f"[{name}](compliance/{name}-compliance-report.md)"

    if p["restricted"] > 0:
        status = "❌ ACTION"
    elif p["unknown_license"] > 0 or p["missing_license"] > 0:
        status = "⚠️ REVIEW"
    else:
        status = "✅ OK"

    lines.append(f"| {report_link} | {p['total_components']} | {p['approved']} | {p['restricted']} | {p['copyleft']} | {p['unknown_license']} | {p['missing_license']} | {p['export_flagged']} | {status} |")

lines.append("")

# Restricted license details across portfolio
all_restricted = []
for p in projects:
    for d in p.get("restricted_details", []):
        all_restricted.append({"project": p["project"], "name": d["name"], "license": d["license"]})

if all_restricted:
    lines.append("## ❌ Restricted Licenses Across Portfolio")
    lines.append("")
    lines.append("| Project | Package | License |")
    lines.append("|---------|---------|---------|")
    for item in sorted(all_restricted, key=lambda x: (x["project"], x["name"])):
        lines.append(f"| {item['project']} | {item['name']} | {item['license']} |")
    lines.append("")

# Export control details across portfolio
all_export = []
for p in projects:
    for d in p.get("export_details", []):
        all_export.append({"project": p["project"], "name": d["name"]})

if all_export:
    lines.append("## 🔒 Export Control Flags Across Portfolio")
    lines.append("")
    lines.append("| Project | Package |")
    lines.append("|---------|---------|")
    for item in sorted(all_export, key=lambda x: (x["project"], x["name"])):
        lines.append(f"| {item['project']} | {item['name']} |")
    lines.append("")

# Recommendations
lines.append("## Recommendations")
lines.append("")
if total_restricted > 0:
    lines.append("- **Immediate:** Review and resolve restricted license usage before deployment to government customers.")
if total_unknown > 0:
    lines.append("- **Short-term:** Add unknown licenses to the compliance policy after legal review.")
if total_missing > 0:
    lines.append("- **Short-term:** Investigate packages with missing license data — check upstream repos manually.")
if total_copyleft > 0:
    lines.append("- **Review:** Verify copyleft-licensed packages are used in a way that doesn't trigger copyleft obligations.")
if total_export > 0:
    lines.append("- **Export compliance:** Have your export control team review flagged cryptography packages for BIS/EAR classification.")
if total_restricted == 0 and total_unknown == 0 and total_missing == 0:
    lines.append("- All licenses are approved. Continue monitoring for license changes in dependency updates.")
lines.append("")

with open(output_file, "w") as f:
    f.write("\n".join(lines))
PYEOF

    # Clean up temp file
    rm -f "$all_summaries"
}
