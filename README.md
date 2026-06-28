# 🛡️ AI Security Research

> **Offensive security research, PoC tooling, and documented attack techniques for ethical hackers and bug bounty hunters.**
> 
> Maintained by [RASTTHACK](https://github.com/rastthack) · Dhaka, Bangladesh

---

## ⚠️ Legal Disclaimer

All research, tools, and techniques in this repository are intended **strictly for educational purposes and authorized security testing only**.

- Do NOT use any technique here against systems you do not own or have explicit written permission to test.
- Always verify that a bug bounty program explicitly permits the attack class you intend to test.
- The author assumes no liability for misuse of this material.

---

## 📂 Repository Structure

```
ai-security-research/
│
├── README.md                          ← You are here
│
├── dependency-confusion/              ← Supply chain attack research
│   ├── README.md                      ← Full attack walkthrough
│   ├── tools/
│   │   ├── check_squattable.py        ← Recon: find squattable package names
│   │   └── monitor_callbacks.sh       ← Monitor interactsh for hits
│   ├── payloads/
│   │   ├── npm_payload/               ← Detection-only npm package template
│   │   │   ├── package.json
│   │   │   └── preinstall.js
│   │   └── pypi_payload/              ← Detection-only PyPI package template
│   │       └── setup.py
│   └── reports/
│       └── report_template.md         ← Bug bounty report template
│
└── [more modules coming soon...]
```

---

## 🗂️ Research Modules

| Module | Technique | Severity | Status |
|--------|-----------|----------|--------|
| [Dependency Confusion](./dependency-confusion/) | Supply Chain / Package Hijacking | 🔴 Critical | ✅ Complete |
| Prompt Injection | LLM / AI Security | 🔴 Critical | 🔜 Coming Soon |
| JWT Abuse | Authentication Bypass | 🟠 High | 🔜 Coming Soon |
| BOLA / IDOR | Broken Object Level Authorization | 🟠 High | 🔜 Coming Soon |
| LLM Data Exfil | AI Model Attacks | 🔴 Critical | 🔜 Coming Soon |

---

## 🧰 Tools Used Across This Repo

- **Recon:** `gh` CLI, `docker`, `nmap`, `shodan`
- **Interception:** Burp Suite Pro, OWASP ZAP
- **Callback:** [interactsh](https://github.com/projectdiscovery/interactsh), Burp Collaborator
- **Package Registries:** npm, PyPI, RubyGems
- **Automation:** Python 3, Bash

---

## 🏆 Bug Bounty Programs This Research Targets

This research is designed for programs on:
- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [YesWeHack](https://yeswehack.com)

Look for programs with scope that includes `supply chain`, `CI/CD`, `build pipeline`, or `third-party dependencies`.


*If this research helped you, consider giving the repo a ⭐ and sharing responsibly.*
