# NVD Vault

Desktop-приложение для аудита уязвимостей по open-source-инвентарю с risk-based приоритизацией патчинга.

Принимает `inventory.json`, обращается к NVD, EPSS и CISA KEV, затем генерирует **vault** в формате связанных Markdown-заметок и предоставляет встроенный просмотрщик с поиском, графом связей и аналитическим дашбордом.

![Python](https://img.shields.io/badge/python-3.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![CI](https://github.com/MortalYar/nvd-vault/actions/workflows/tests.yml/badge.svg)

---

## Features

- Build vulnerability vault from `inventory.json`
- Automatic vendor discovery via NVD CPE Dictionary
- Accurate CPE 2.3 version matching with range support
- Risk-based prioritization using **CVSS + EPSS + CISA KEV**
- Markdown knowledge graph with wiki-links between CVE / Product / CWE
- Interactive dashboard with KPIs and risk analytics
- Full-text search via SQLite FTS5
- Interactive graph visualization via Cytoscape.js
- Export vault as ZIP archive
- GUI mode + CLI build mode

---

## Installation

```bash
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault
python -m pip install -e ".[dev]"
```

> Requires Python 3.13.  
> Python 3.14 is currently unsupported due to `pythonnet` dependency limitations.

---

## Usage

### GUI Mode

```bash
nvd-vault
```

or:

```bash
python app.py
```

---

### CLI Mode

```bash
nvd-vault build examples/sample_inventory.json --out ./vault
```

If `--out` is omitted, output path will be requested interactively.

---

## Inventory Format

```json
{
  "vault_name": "My ELK Stack",
  "products": [
    { "name": "kibana", "version": "8.19.9", "vendor": "elastic" },
    { "name": "logstash", "version": "8.19.5", "vendor": "elastic" }
  ]
}
```

---

## Generated Vault Structure

```text
vault/
├── meta.json
├── cves/
├── products/
└── cwes/
```

---

## Risk Prioritization Model

| Risk Tier | Condition | Recommended Action |
|---|---|---|
| `critical_now` | Present in CISA KEV | Patch immediately |
| `critical_likely` | EPSS ≥ 0.7 | Patch within days |
| `high` | CVSS ≥ 8.0 or EPSS ≥ 0.3 | Prioritized patching |
| `medium` | CVSS ≥ 5.0 | Standard workflow |
| `low` | Everything else | Opportunistic patching |

---

## Development

Run tests:

```bash
python -m pytest
```

GitHub Actions automatically runs CI on push / PR.

---

## NVD API Key

Recommended for larger inventories.

Without key:
- **5 requests / 30 sec**

With key:
- **50 requests / 30 sec**

Get key here:  
https://nvd.nist.gov/developers/request-an-api-key

Set environment variable:

### PowerShell

```powershell
$env:NVD_API_KEY="your_api_key_here"
```

### Linux/macOS

```bash
export NVD_API_KEY="your_api_key_here"
```

---

## Limitations

- Currently focused on **Application CPE** (`cpe:2.3:a:`)
- Depends on NVD CPE quality / completeness
- CVE descriptions remain in English
- Primarily tested on Windows 11

---

## Related Project

- [nvd-scanner](https://github.com/MortalYar/nvd-scanner) — CLI predecessor

---

## License

MIT — see [LICENSE](LICENSE)