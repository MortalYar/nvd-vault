# Security Policy

**English** · [Русский](SECURITY.ru.md)

NVD Vault is a security-adjacent tool — it helps users audit their software inventories for known vulnerabilities. We take the security of the tool itself seriously and appreciate responsible disclosure of any issues.

## Supported Versions

NVD Vault is in early active development. Only the latest release on the `main` branch receives security fixes. Older commits and pre-release tags are not patched — please update to the latest version before reporting.

| Version       | Supported          |
| ------------- | ------------------ |
| `main` (latest) | :white_check_mark: |
| `0.1.x`         | :white_check_mark: |
| `< 0.1`         | :x:                |

Once the project reaches a stable `1.0` release, this policy will be updated to cover a longer support window for the latest minor versions.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Instead, please use one of the following private channels:

- **Preferred:** [GitHub Security Advisories](https://github.com/MortalYar/nvd-vault/security/advisories/new) — opens a private report visible only to maintainers.
- **Alternative:** open a minimal public issue titled *"Security contact request"* (no details) and the maintainer will reach out privately.

When reporting, please include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal proof-of-concept is ideal)
- The affected version, commit hash, or release tag
- Your operating system and Python version
- Any suggested mitigation, if you have one

## What to Expect

| Stage                          | Target timeline                                  |
| ------------------------------ | ------------------------------------------------ |
| Initial acknowledgement        | Within **72 hours** of the report                |
| Triage and severity assessment | Within **7 days**                                |
| Status updates during fix      | At least once every **14 days**                  |
| Fix release (critical/high)    | Within **30 days** of confirmation, when feasible |
| Public disclosure              | Coordinated with the reporter after a fix ships  |

If a vulnerability is **accepted**, you can expect:

- Confirmation and a CVE request via GitHub Security Advisories where applicable
- A patched release on `main` and a tagged version
- Credit in the advisory and release notes (unless you prefer to remain anonymous)

If a vulnerability is **declined** (for example, behaviour considered out of scope, or already a known limitation), you will receive a written explanation of the reasoning, and you are free to disclose publicly afterwards.

## Scope

**In scope:**

- Code in this repository (`nvd_vault/`, `app.py`, packaging files)
- Default configurations and shipped examples
- The bundled web UI and IPC layer between the Python backend and the embedded browser

**Out of scope:**

- Vulnerabilities in third-party services queried by the tool (NVD API, EPSS, CISA KEV) — please report those upstream
- Vulnerabilities in third-party dependencies that have no exploitable path from NVD Vault — please report those to the dependency maintainer
- Issues that require the attacker to already have local code execution or write access to the user's vault directory
- Social engineering, physical attacks, or attacks on the user's GitHub account

## Safe Harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy
- Report promptly and do not publicly disclose before a coordinated date
- Avoid privacy violations, data destruction, and service degradation
- Only test against their own installations and data

Thank you for helping keep NVD Vault and its users safe.
