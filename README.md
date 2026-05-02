# NVD Vault

**English** · [Русский](README.ru.md)

Local desktop application for vulnerability auditing of open-source inventories with risk-based patch prioritization using CVSS, EPSS, and CISA KEV.

Takes `inventory.json` or SBOM (CycloneDX / SPDX) as input. Produces a **vault** of linked Markdown notes (CVE / Product / CWE), plus a built-in browser with full-text search, relationship graph, and analytical dashboard.

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![CI](https://github.com/MortalYar/nvd-vault/actions/workflows/tests.yml/badge.svg)

---

## Why this exists

The standard security-engineer scenario: "We have Kibana 8.19, Logstash 8.19, OpenSSL 3.0, and nginx 1.24 — what's critical, and what should we patch first?"

NVD Vault answers this automatically:

1. Takes the list of software and versions.
2. Calls the NVD API and finds all CVEs for each product.
3. Enriches the results with EPSS data (exploitation probability) and CISA KEV (known active exploitation).
4. Produces a prioritized list with clear tiers: `critical_now` / `critical_likely` / `high` / `medium` / `low`.
5. Stores everything locally as Markdown — open it in Obsidian, hand it to auditors, or browse it in the built-in UI.

Unlike SaaS scanners like Snyk or GitHub Dependabot, **everything runs locally** — your inventory never leaves the machine. Only public NVD API requests with component names go out.

---

## Features

- Build a vault from `inventory.json` or SBOM (CycloneDX / SPDX)
- Automatic vendor discovery via NVD CPE Dictionary
- Accurate CPE 2.3 matching with version range and pre-release support
- Risk-based prioritization: **CVSS + EPSS + CISA KEV**
- Markdown knowledge graph with `[[wiki-links]]` between CVE, Product, and CWE
- Interactive dashboard with KPIs and risk analytics
- Full-text search via SQLite FTS5
- Interactive graph visualization via Cytoscape.js (with PNG export)
- Export the vault as a ZIP archive
- GUI and CLI modes
- CISA KEV catalog cached (1h TTL) — fast repeat scans
- Robust NVD rate-limit handling with no false failures

---

## Quick start

### Installation

```bash
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault
python -m pip install -e ".[dev]"
```

> Requires Python 3.11 or newer. Tested on 3.11, 3.12, 3.13.

### Launching the GUI

```bash
nvd-vault
```

or equivalently:

```bash
python app.py
```

### Building a vault via CLI

```bash
nvd-vault build examples/sample_inventory.json --out ./vault
```

If `--out` is omitted, the output path will be requested interactively.

---

## Inventory format

```json
{
  "vault_name": "Production_ELK_Cluster",
  "products": [
    { "name": "kibana", "version": "8.19.9", "vendor": "elastic" },
    { "name": "logstash", "version": "8.19.5", "vendor": "elastic" },
    { "name": "openssl", "version": "3.0.11", "vendor": "openssl" }
  ]
}
```

The `vendor` field is optional — if omitted, NVD Vault will try to find the vendor automatically through the CPE Dictionary. If multiple candidates exist, the GUI opens a picker dialog.

### Supported SBOM formats

- **CycloneDX JSON** (`bomFormat: "CycloneDX"`)
- **SPDX JSON** (`spdxVersion` field present)

```bash
nvd-vault build sbom.cyclonedx.json --input-format sbom --out ./vault
```

Format auto-detection works based on JSON content:

```bash
nvd-vault build sbom.cyclonedx.json --out ./vault
```

---

## Generated vault structure

```text
vault/
├── meta.json                  # vault metadata (name, build date, statistics)
├── search.db                  # SQLite FTS5 index
├── cves/
│   ├── CVE-2024-XXXXX.md
│   └── ...
├── products/
│   ├── kibana.md              # vulnerability summary per product
│   └── ...
└── cwes/
    ├── CWE-79.md
    └── ...
```

Each `.md` note has a YAML frontmatter with metadata (CVSS, EPSS, KEV, ransomware flag, risk tier) and a human-readable body with `[[wiki-links]]` to other notes.

The vault is fully **Obsidian-compatible** — you can open the folder as an Obsidian Vault and use its features (graph, search, plugins) on top.

---

## Risk prioritization model

| Tier | Condition | What to do |
|---|---|---|
| `critical_now` | Listed in CISA KEV (actively exploited in the wild) | **Patch immediately**, treat as P0 |
| `critical_likely` | EPSS ≥ 0.7 (high probability of exploitation in the next 30 days) | Patch within days |
| `high` | CVSS ≥ 8.0 or EPSS ≥ 0.3 | Schedule for next patching window |
| `medium` | CVSS ≥ 5.0 | Standard workflow |
| `low` | Everything else | Opportunistic patching |

### What these acronyms mean

- **CVSS** (Common Vulnerability Scoring System) — a standardized severity score from 0.0 to 10.0. Considers the attack vector, exploitation complexity, required privileges, and impact on confidentiality/integrity/availability. CVSS alone tells you "how *bad* if exploited", but not "how *likely* to be exploited".
- **EPSS** (Exploit Prediction Scoring System) — probability of exploitation in the next 30 days, a number from 0.0 to 1.0. Computed daily by FIRST using an ML model trained on real attacks, exploit kits, and Twitter/GitHub mentions. Complements CVSS: high CVSS + low EPSS means "theoretically dangerous, but no one is attacking it"; low CVSS + high EPSS means "being actively exploited".
- **CISA KEV** (Known Exploited Vulnerabilities) — a catalog of vulnerabilities **confirmed to be actively exploited**. Maintained by the U.S. Cybersecurity and Infrastructure Security Agency. If a CVE is in KEV, it's being used in real-world attacks and you should have patched it yesterday.

---

## Getting an NVD API key

**Strongly recommended** for any build of more than 5–10 products.

| Without a key | With a key |
|---|---|
| 5 requests / 30 seconds | 50 requests / 30 seconds |
| Building 20 products ≈ 2 minutes | Building 20 products ≈ 12 seconds |

A free API key is available here:

> https://nvd.nist.gov/developers/request-an-api-key

The key arrives by email in a few minutes. Usage:

### PowerShell (Windows)

```powershell
$env:NVD_API_KEY="your_api_key_here"
```

Or persistently:

```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "your_api_key_here", "User")
```

### Linux / macOS

```bash
export NVD_API_KEY="your_api_key_here"
```

The CLI also accepts the key directly:

```bash
nvd-vault build inventory.json --api-key your_api_key_here --out ./vault
```

---

## User interface

The application has four tabs:

- **Build Vault** — inventory editor + build runner. Load an existing JSON or build the list by hand, with vendor auto-discovery via NVD.
- **Dashboard** — KPIs for the vault (total CVEs, exploited, ransomware, CISA-overdue), top products and CWEs, remediation plan.
- **Graph** — Cytoscape visualization of links between CVEs, products, and CWEs. Filter by risk tier, export to PNG.
- **Browse Vault** — note browser with risk-tier highlighting, KEV/ransomware icons, full-text search, and wiki-link navigation.

---

## Comparison with other tools

| Tool | Type | Inventory source | Risk score | Local-only | Open source |
|---|---|---|---|---|---|
| **NVD Vault** | Desktop GUI | manual JSON / SBOM | CVSS + EPSS + KEV | yes | yes (MIT) |
| Snyk | SaaS | git/SBOM auto | proprietary | no | freemium |
| GitHub Dependabot | SaaS | repo auto | CVSS | no | yes (for public repos) |
| OWASP Dependency-Check | CLI | maven/gradle/npm/etc. | CVSS | yes | yes |
| Trivy | CLI | container/SBOM/repo | CVSS | yes | yes |
| Grype | CLI | SBOM | CVSS | yes | yes |
| Vulners | SaaS | manual API | CVSS+exploit | no | freemium |

**Choose NVD Vault when:**
- You need a **local** audit without sending data to the cloud.
- You want EPSS+KEV-based prioritization, not just CVSS.
- You want **linked Markdown notes** for further work (reports, ticketing, write-ups), not just a flat CVE list.
- Your inventory is a "list of software running on production servers", not a build artifact.

**Choose something else when:**
- You need CI/CD integration on every pull request → Trivy / Grype / Dependabot.
- You're scanning Docker images → Trivy / Grype.
- You have Java/Node projects with package-manager dependencies → OWASP Dependency-Check.
- You need an enterprise dashboard for a whole team → Snyk / Vulners / similar.

---

## FAQ

### How often should I rebuild the vault?

Whenever your software inventory changes, or when you want fresh CVE/EPSS/KEV data. NVD updates CVEs **daily**; EPSS and KEV update daily as well. Rebuilding a 30-product vault with an API key takes 30–60 seconds.

### NVD is unavailable / 403 / slow

NVD has occasional outages. NVD Vault correctly handles rate limits (5 req/30s without a key, 50 with a key) and automatically retries on 5xx errors. If you keep getting 403 without a key — get a key (see above).

### Does it work offline?

After the build — **yes**: vault browsing, graph, search, and ZIP export don't need network. The build itself requires access to `services.nvd.nist.gov`, `api.first.org` (EPSS), and `cisa.gov` (KEV).

The UI partially relies on Google Fonts CDN — without internet, fonts will fall back to system defaults, but functionality is preserved. JS libraries (cytoscape, marked) are vendored locally.

### Crashes with `ImportError: webview` on startup

The virtualenv isn't active or dependencies aren't installed:

```bash
# Linux/macOS
source venv/bin/activate
python -m pip install -e ".[dev]"
```

```powershell
# Windows
.\venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

### The vault shows "0 products, 0 CVEs"

Most likely the vendor wasn't auto-detected. Possible causes:
1. The product name doesn't match what NVD calls it (e.g., `apache` vs `httpd`). Open <https://nvd.nist.gov/products/cpe/search>, find your product, see its CPE name, and update the inventory.
2. The vendor field is missing and auto-discovery returned no results. Set it manually via the GUI (magnifier button next to the vendor input).
3. The version is in a format NVD doesn't recognize (e.g., distro-specific suffixes). Try a clean upstream version.

### Can I use it commercially?

Yes — MIT license.

### Is version comparison correct?

NVD Vault uses `packaging.version` (PEP 440), which correctly handles most open-source schemes including pre-release (`1.0.0-rc2 < 1.0.0-rc10 < 1.0.0`). For exotic versions (e.g., distro-style `5.7.32-0ubuntu0.18.04.1`), there's a fallback parser. If you encounter a case that's compared incorrectly — please open an issue.

### What do I do with a long `critical_now` list?

`critical_now` means "active exploitation confirmed by CISA". These are P0 even if the CVSS isn't max. Patch in order of presence in your infrastructure, starting with externally-exposed systems.

---

## Troubleshooting

**Issue:** Running `python app.py` opens a blank black window
**Fix:** Verify that `nvd_vault/webui/vendor/` is not empty (5 JS files: marked, cytoscape, cose-bilkent plugins). If empty — re-clone the repo or fetch the files per the README in `vendor/`.

**Issue:** `ModuleNotFoundError: No module named 'packaging'`
**Fix:** You upgraded from an older version. Run `pip install -e ".[dev]"` again to refresh dependencies.

**Issue:** All CVEs come out as `low`-tier when they should be critical
**Fix:** EPSS/KEV enrichment failed silently. Verify that `api.first.org` and `cisa.gov` are reachable from your network. Build-time logs (`logger.warning`) will show if any requests failed.

**Issue:** Vault build hangs on a single product
**Fix:** That product likely has thousands of CVEs in NVD, and pagination is slow. With an API key, it's much faster. You can monitor progress in the GUI build log (Build tab, log at the bottom).

**Issue:** Empty or weird-looking graph
**Fix:** The graph only renders if the vault has **links** between notes (via `[[wiki-link]]`). If you only have products without CVEs — there are no links, and the graph is empty. This is expected.

---

## Development

### Running tests

```bash
python -m pytest -v
```

CI is configured through GitHub Actions, running on every push and PR.

### Project structure

```text
nvd-vault/
├── app.py                   # entry point (CLI + GUI)
├── nvd_vault/
│   ├── core/                # business logic
│   │   ├── nvd_client.py    # NVD API HTTP client
│   │   ├── enrichment.py    # EPSS, KEV, risk score
│   │   ├── matcher.py       # CPE 2.3 + version comparison
│   │   ├── frontmatter.py   # YAML frontmatter parser
│   │   ├── vault_builder.py # build orchestrator
│   │   ├── markdown_writer.py
│   │   ├── dashboard.py
│   │   ├── graph_builder.py
│   │   ├── search_index.py  # SQLite FTS5
│   │   ├── remediation.py
│   │   ├── inventory.py     # inventory.json parser
│   │   └── sbom.py          # CycloneDX/SPDX parser
│   ├── api/
│   │   └── bridge.py        # JS↔Python API via pywebview
│   └── webui/
│       ├── index.html
│       ├── css/
│       ├── js/
│       └── vendor/          # vendored cytoscape, marked
├── tests/
└── examples/                # sample inventory and SBOM files
```

### Contributing

PRs are welcome. Before submitting:
1. Run the tests (`pytest`).
2. If you changed logic — add a test for it.
3. PR description in either language (EN or RU) is fine.

---

## Limitations

- Targets **Application CPE** (`cpe:2.3:a:`). OS-CPE and Hardware-CPE are not supported.
- Result quality depends on **CPE coverage in NVD**. If NVD hasn't tagged a product with a CPE, the vault won't see it.
- CVE descriptions remain in **English** (as they are in NVD).
- Primary development and testing on **Windows 11**. Linux and macOS should work (pywebview is cross-platform), but are less thoroughly tested.
- **Not designed for Docker image scanning** — use Trivy or Grype for that.

---

## Related projects

- [nvd-scanner](https://github.com/MortalYar/nvd-scanner) — CLI predecessor of this project

---

## License

MIT — see [LICENSE](LICENSE).