#!/usr/bin/env bash
# lib/enrich.sh — Enrich scan results with exploitation intelligence
# KEV: CISA Known Exploited Vulnerabilities catalog (confirmed exploitation in the wild)
# EPSS: FIRST.org Exploit Prediction Scoring System (30-day exploitation probability)

KEV_FEED_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL="https://api.first.org/data/v1/epss"

# Download the KEV catalog and reduce it to a CVE-keyed map.
# Writes {"CVE-...": {"kev": true, "kev_date_added": "...", "kev_ransomware": bool}, ...}
fetch_kev_map() {
    local output_file="$1"

    python3 - "$KEV_FEED_URL" "$output_file" << 'PYEOF'
import json, sys, urllib.request

url, output_file = sys.argv[1], sys.argv[2]

try:
    req = urllib.request.Request(url, headers={"User-Agent": "vulnsweep"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        catalog = json.load(resp)
except Exception as e:
    print(f"  WARNING: KEV catalog fetch failed: {e}", file=sys.stderr)
    sys.exit(1)

kev_map = {}
for v in catalog.get("vulnerabilities", []):
    cve = v.get("cveID")
    if not cve:
        continue
    kev_map[cve] = {
        "kev": True,
        "kev_date_added": v.get("dateAdded", ""),
        "kev_ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
    }

with open(output_file, "w") as f:
    json.dump(kev_map, f)

print(f"  KEV catalog: {len(kev_map)} actively exploited CVEs", file=sys.stderr)
PYEOF
}

# Enrich one project's trivy JSON: look up every CVE against the KEV map and
# the EPSS API, and merge the results into the scan-wide enrichment file.
# Writes/updates {"CVE-...": {"epss": 0.97, "percentile": 0.99, "kev": true, ...}, ...}
enrich_project() {
    local json_file="$1"
    local kev_map_file="$2"
    local enrich_file="$3"

    python3 - "$json_file" "$kev_map_file" "$enrich_file" "$EPSS_API_URL" << 'PYEOF'
import json, sys, urllib.request

json_file, kev_map_file, enrich_file, epss_url = sys.argv[1:5]

with open(json_file) as f:
    scan = json.load(f)

cves = set()
for result in scan.get("Results") or []:
    for vuln in result.get("Vulnerabilities") or []:
        vid = vuln.get("VulnerabilityID", "")
        if vid.startswith("CVE-"):
            cves.add(vid)

kev_map = {}
try:
    with open(kev_map_file) as f:
        kev_map = json.load(f)
except (OSError, json.JSONDecodeError):
    pass

enrichment = {}
try:
    with open(enrich_file) as f:
        enrichment = json.load(f)
except (OSError, json.JSONDecodeError):
    pass

new_cves = sorted(c for c in cves if c not in enrichment)

# Batch EPSS lookups (API accepts comma-separated CVE lists)
epss_scores = {}
epss_failed = False
for i in range(0, len(new_cves), 100):
    batch = new_cves[i:i + 100]
    url = f"{epss_url}?cve={','.join(batch)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vulnsweep"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        for row in data.get("data", []):
            epss_scores[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
    except Exception as e:
        epss_failed = True
        print(f"  WARNING: EPSS lookup failed for batch of {len(batch)}: {e}", file=sys.stderr)

for cve in new_cves:
    entry = {"epss": None, "percentile": None, "kev": False}
    entry.update(epss_scores.get(cve, {}))
    entry.update(kev_map.get(cve, {}))
    enrichment[cve] = entry

with open(enrich_file, "w") as f:
    json.dump(enrichment, f)

kev_hits = sum(1 for c in cves if enrichment.get(c, {}).get("kev"))
if kev_hits:
    print(f"  ⚠️  {kev_hits} CVE(s) in CISA KEV — actively exploited", file=sys.stderr)
sys.exit(2 if epss_failed else 0)
PYEOF
    local rc=$?
    # rc 2 = partial (EPSS unreachable); treat as success, KEV data still merged
    [[ $rc -eq 0 || $rc -eq 2 ]]
}
