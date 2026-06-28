#!/usr/bin/env python3
"""
check_squattable.py — RASTTHACK AI Security Research
Batch-check package names across npm and PyPI to identify squattable names
for dependency confusion bug bounty research.

Usage:
    python3 check_squattable.py --names pkg1 pkg2 pkg3
    python3 check_squattable.py --file names.txt
    python3 check_squattable.py --names company-auth company-sdk --registries npm pypi

LEGAL: Use only against targets you are authorized to test.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

BANNER = f"""
{CYAN}{BOLD}╔═══════════════════════════════════════════════╗
║   check_squattable.py — RASTTHACK Research    ║
║   Dependency Confusion — Package Checker      ║
╚═══════════════════════════════════════════════╝{RESET}
"""


# ─────────────────────────────────────────────
# Registry checks
# ─────────────────────────────────────────────

def check_npm(package_name: str) -> dict:
    """Check if a package name is available on npm."""
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rastthack-security-research/1.0"})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read())
            latest = data.get("dist-tags", {}).get("latest", "unknown")
            return {
                "registry": "npm",
                "package": package_name,
                "squattable": False,
                "latest_version": latest,
                "url": f"https://npmjs.com/package/{package_name}"
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "registry": "npm",
                "package": package_name,
                "squattable": True,
                "latest_version": None,
                "url": f"https://npmjs.com/package/{package_name}"
            }
        return {"registry": "npm", "package": package_name, "squattable": None, "error": str(e)}
    except Exception as e:
        return {"registry": "npm", "package": package_name, "squattable": None, "error": str(e)}


def check_pypi(package_name: str) -> dict:
    """Check if a package name is available on PyPI."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rastthack-security-research/1.0"})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read())
            latest = data.get("info", {}).get("version", "unknown")
            return {
                "registry": "pypi",
                "package": package_name,
                "squattable": False,
                "latest_version": latest,
                "url": f"https://pypi.org/project/{package_name}"
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "registry": "pypi",
                "package": package_name,
                "squattable": True,
                "latest_version": None,
                "url": f"https://pypi.org/project/{package_name}"
            }
        return {"registry": "pypi", "package": package_name, "squattable": None, "error": str(e)}
    except Exception as e:
        return {"registry": "pypi", "package": package_name, "squattable": None, "error": str(e)}


def check_rubygems(package_name: str) -> dict:
    """Check if a gem name is available on RubyGems."""
    url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rastthack-security-research/1.0"})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read())
            latest = data.get("version", "unknown")
            return {
                "registry": "rubygems",
                "package": package_name,
                "squattable": False,
                "latest_version": latest,
                "url": f"https://rubygems.org/gems/{package_name}"
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "registry": "rubygems",
                "package": package_name,
                "squattable": True,
                "latest_version": None,
                "url": f"https://rubygems.org/gems/{package_name}"
            }
        return {"registry": "rubygems", "package": package_name, "squattable": None, "error": str(e)}
    except Exception as e:
        return {"registry": "rubygems", "package": package_name, "squattable": None, "error": str(e)}


REGISTRY_MAP = {
    "npm": check_npm,
    "pypi": check_pypi,
    "rubygems": check_rubygems,
}


# ─────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────

def print_result(result: dict):
    pkg  = result["package"]
    reg  = result["registry"].upper()

    if result.get("squattable") is True:
        print(f"  {RED}[SQUATTABLE]{RESET} {BOLD}{pkg}{RESET} on {CYAN}{reg}{RESET} — name is FREE")
    elif result.get("squattable") is False:
        ver = result.get("latest_version", "?")
        print(f"  {GREEN}[TAKEN]{RESET}      {pkg} on {reg} — v{ver}")
    else:
        err = result.get("error", "unknown error")
        print(f"  {YELLOW}[ERROR]{RESET}      {pkg} on {reg} — {err}")


def print_summary(results: list):
    squattable = [r for r in results if r.get("squattable") is True]
    taken      = [r for r in results if r.get("squattable") is False]
    errors     = [r for r in results if r.get("squattable") is None]

    print(f"\n{BOLD}{'─'*50}")
    print(f"SUMMARY — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*50}{RESET}")
    print(f"  Total checked : {len(results)}")
    print(f"  {RED}Squattable    : {len(squattable)}{RESET}")
    print(f"  {GREEN}Taken         : {len(taken)}{RESET}")
    print(f"  {YELLOW}Errors        : {len(errors)}{RESET}")

    if squattable:
        print(f"\n{RED}{BOLD}🎯 POTENTIAL TARGETS:{RESET}")
        for r in squattable:
            print(f"   → {r['package']} on {r['registry'].upper()}")

    print()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Dependency confusion squattable package checker — RASTTHACK"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--names", nargs="+", help="Package names to check")
    group.add_argument("--file", help="File with one package name per line")
    parser.add_argument(
        "--registries",
        nargs="+",
        choices=["npm", "pypi", "rubygems"],
        default=["npm", "pypi"],
        help="Registries to check (default: npm pypi)"
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--output", help="Save results to JSON file"
    )
    args = parser.parse_args()

    # Load names
    if args.names:
        names = args.names
    else:
        try:
            with open(args.file) as f:
                names = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{RED}Error: file not found: {args.file}{RESET}")
            sys.exit(1)

    registries = args.registries
    print(f"{BOLD}Checking {len(names)} package(s) across: {', '.join(r.upper() for r in registries)}{RESET}\n")

    # Build tasks
    tasks = []
    for name in names:
        for reg in registries:
            tasks.append((name, reg))

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(REGISTRY_MAP[reg], name): (name, reg)
            for name, reg in tasks
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print_result(result)

    print_summary(results)

    # Save output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{CYAN}Results saved to: {args.output}{RESET}")


if __name__ == "__main__":
    main()
