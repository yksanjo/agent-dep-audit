#!/usr/bin/env python3
"""Synthetic demo: a compromised-looking project and a clean one.

All fixtures are invented. Any resemblance to real packages beyond the
well-known names in the typosquat target list is coincidental.
"""

import json
import os
import tempfile

import dep_audit

COMPROMISED = {
    "name": "demo-agent",
    "dependencies": {
        "1itellm": "*",                       # 1 edit from litellm + unpinned
        "express": "^4.21.0",                 # loose range
        "helper-lib": "git+https://example.com/helper.git",  # non-registry
        "ghost-dep": "2.1.0",                     # declared, absent from lock
    },
}
COMPROMISED_LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {},
        "node_modules/1itellm": {
            "version": "9.9.9",
            "resolved": "https://packages.evil-mirror.example/1itellm-9.9.9.tgz",
            "hasInstallScript": True,
        },
        "node_modules/express": {"version": "4.21.2"},
        # ghost-dep intentionally absent: lockfile drift
    },
}

CLEAN = {"name": "demo-agent", "dependencies": {"express": "4.21.2"}}
CLEAN_LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {},
        "node_modules/express": {
            "version": "4.21.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz",
        },
    },
}


def build(manifest, lock):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "package.json"), "w") as f:
        json.dump(manifest, f)
    with open(os.path.join(d, "package-lock.json"), "w") as f:
        json.dump(lock, f)
    return d


def main():
    for label, manifest, lock in (
        ("compromised-looking project", COMPROMISED, COMPROMISED_LOCK),
        ("clean project", CLEAN, CLEAN_LOCK),
    ):
        d = build(manifest, lock)
        print("=== %s (%s) ===" % (label, d))
        findings = dep_audit.audit(d)
        print(dep_audit.format_text(findings) if findings else "no findings")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
