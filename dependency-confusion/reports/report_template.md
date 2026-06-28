# Bug Bounty Report — Dependency Confusion Attack

> **Template by RASTTHACK — Fill in all [BRACKETS] before submitting**

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Title** | Dependency Confusion — `[PACKAGE_NAME]` — RCE in [CI/CD / Developer Environment] |
| **Researcher** | RASTTHACK |
| **Date Found** | [YYYY-MM-DD] |
| **Date Reported** | [YYYY-MM-DD] |
| **Severity** | Critical / High / Medium |
| **CVSS Score** | [9.8 / 8.x / 7.x] |
| **Affected Asset** | [URL or description of affected system] |

---

## Executive Summary

The internal npm/PyPI package `[PACKAGE_NAME]` used by [TARGET COMPANY] is not registered on the public [npm/PyPI] registry. By registering a package with the same name and a higher version (`99.99.1`), a remote attacker can achieve **arbitrary code execution** on [TARGET COMPANY]'s [CI/CD pipeline / developer machines] during dependency installation.

I confirmed this vulnerability using a **detection-only payload** (DNS + HTTP callback) with no destructive actions. The callback was received at `[TIMESTAMP]` from host `[HOSTNAME]`, indicating a [production build server / developer machine / staging environment].

---

## Vulnerability Details

**Type:** Dependency Confusion / Supply Chain Attack  
**CWE:** CWE-1357 — Reliance on Insufficiently Trustworthy Component  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`  
**CVSS Score:** 9.8 (Critical)

---

## Affected Package

| Field | Value |
|-------|-------|
| Package Name | `[PACKAGE_NAME]` |
| Registry | [npm / PyPI / RubyGems] |
| Internal Version | [v1.x.x — if known] |
| Attacker Version | v99.99.1 |
| Public URL | [https://npmjs.com/package/PACKAGE_NAME] |

---

## Steps to Reproduce

### Step 1 — Identify Internal Package Name

[Describe how you found the internal package name]

Examples:
- Found in `package.json` at: [URL to public repo/file]
- Found in CI/CD log at: [URL]
- Found in Docker image layer: `docker history [image]`

### Step 2 — Confirm Name is Unregistered Publicly

```bash
npm show [PACKAGE_NAME]
# Output: npm ERR! 404 Not Found - GET https://registry.npmjs.org/[PACKAGE_NAME]
```

### Step 3 — Register Detection-Only Package

Registered `[PACKAGE_NAME]` on [npm/PyPI] with version `99.99.1`.  
Package contained only a DNS + HTTP callback payload pointing to `[INTERACTSH_URL]`.  
No destructive code was included.

### Step 4 — Callback Received

```
[TIMESTAMP]: DNS callback received from [IP_ADDRESS]
[TIMESTAMP]: HTTP callback received
Decoded data:
{
  "host": "[HOSTNAME]",
  "platform": "[linux/windows/darwin]",
  "user": "[username]",
  "ci": [true/false],
  "ci_name": "[github-actions/jenkins/none]"
}
```

---

## Evidence

- [ ] Screenshot of interactsh callback log
- [ ] Screenshot of package published on public registry
- [ ] Screenshot of decoded callback data
- [ ] Screenshot of internal package name source (repo/log/etc.)

---

## Impact

An attacker exploiting this vulnerability could:

1. **Execute arbitrary code** on [COMPANY]'s build infrastructure during `npm install` / `pip install`
2. **Exfiltrate secrets** — environment variables, API keys, SSH keys, cloud credentials
3. **Inject backdoors** into build artifacts, affecting all downstream users
4. **Achieve persistent access** to CI/CD systems
5. **Compromise the software supply chain** — malicious code could reach end users

[If CI=true in callback]: The callback originated from a **CI/CD pipeline**, meaning malicious code would run on every build, potentially affecting all software artifacts produced by [COMPANY].

---

## CVSS Justification

| Metric | Value | Reason |
|--------|-------|--------|
| Attack Vector | Network | Exploitable remotely via public package registry |
| Attack Complexity | Low | No special conditions required |
| Privileges Required | None | Any attacker can register a package |
| User Interaction | None | Triggered automatically on `npm install` |
| Scope | Changed | Affects build infrastructure beyond the package itself |
| Confidentiality | High | Full access to build environment secrets |
| Integrity | High | Can inject code into build artifacts |
| Availability | High | Can disrupt build pipelines |

---

## Remediation Recommendations

### Immediate Actions

1. **Register the package name** on the public registry as a placeholder to prevent squatting:
   ```bash
   # npm — publish an empty stub
   npm publish --access public
   
   # PyPI — publish a stub with no functionality
   twine upload dist/*
   ```

2. **Pin to internal registry** in `.npmrc` or `pip.conf`:
   ```ini
   # .npmrc
   registry=https://your-internal-registry.company.com
   
   # pip.conf
   [global]
   index-url = https://your-internal-pypi.company.com/simple/
   extra-index-url = https://pypi.org/simple/
   ```

### Long-Term Fixes

3. **Use scoped packages**: Migrate to `@company/package-name` (npm) to reduce namespace collision risk
4. **Implement hash pinning**: Lock `package-lock.json` entries to specific SHA integrity hashes
5. **Configure Artifactory/Nexus** to always prefer internal registry for conflicting package names
6. **Integrate SCA tooling**: Deploy Snyk, Socket.dev, or Dependabot to alert on suspicious packages

---

## Researcher Notes

- This was a **detection-only payload**. No data was exfiltrated and no systems were harmed.
- The malicious package has been **unpublished** / will be unpublished upon triage confirmation.
- All findings were identified through passive reconnaissance of publicly available information.
- Testing was performed in accordance with [PROGRAM NAME]'s responsible disclosure policy.

---

## References

- [Alex Birsan — Dependency Confusion (2021)](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [OWASP A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)

---

*Report authored by RASTTHACK · [github.com/rastthack](https://github.com/rastthack)*
