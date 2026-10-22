#!/usr/bin/env python3
"""Offline dependency-manifest auditor for agent projects.

Scans an npm project's package.json and package-lock.json for supply-chain
risk signals: unpinned or loose versions, install scripts, lockfile drift,
typosquat-proximate names, non-registry sources, unknown tarball hosts, and
confusable (non-ASCII) package names. It never touches the network, never
installs anything, and cannot block an install. It is a heuristic scanner,
not a vulnerability feed.
"""

import argparse
import json
import sys

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}

# High-value packages an agent project often depends on. Typosquats of these
# are a known malware delivery channel (e.g. the litellm compromise).
TYPOSQUAT_TARGETS = [
    "litellm", "openai", "anthropic", "langchain", "langsmith", "cohere",
    "requests", "urllib3", "httpx", "aiohttp", "boto3", "colorama",
    "react", "express", "axios", "lodash", "chalk", "commander",
    "typescript", "esbuild", "next", "vite", "webpack", "ethers",
    "web3", "solana", "puppeteer", "playwright", "discord.js",
]

NON_REGISTRY_PREFIXES = ("file:", "link:", "git:", "git+", "http:", "https:", "github:", "workspace:")
NPM_REGISTRY_PREFIX = "https://registry.npmjs.org/"


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def finding(code, severity, package, detail, source):
    return {
        "code": code,
        "severity": severity,
        "package": package,
        "detail": detail,
        "source": source,
    }


def check_manifest(manifest, findings):
    for section in ("dependencies", "devDependencies"):
        deps = manifest.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec = str(spec).strip()
            src = "package.json:%s" % section
            # Non-ASCII names are a confusable-homoglyph risk.
            if not name.isascii():
                findings.append(finding(
                    "confusable-name", "warning", name,
                    "package name contains non-ASCII characters (possible homoglyph)", src))
            # Typosquat proximity to high-value targets.
            lowered = name.lower()
            if len(lowered) >= 4 and lowered not in TYPOSQUAT_TARGETS:
                for target in TYPOSQUAT_TARGETS:
                    dist = levenshtein(lowered, target)
                    if dist == 1:
                        findings.append(finding(
                            "typosquat-risk", "error", name,
                            "name is 1 edit from '%s' - verify this is the intended package" % target, src))
                        break
                    elif dist == 2:
                        findings.append(finding(
                            "typosquat-risk", "warning", name,
                            "name is 2 edits from '%s'" % target, src))
                        break
            # Version source and pinning.
            if spec.startswith(NON_REGISTRY_PREFIXES):
                findings.append(finding(
                    "non-registry-source", "warning", name,
                    "dependency resolves outside the npm registry: '%s'" % spec, src))
            elif spec in ("*", "", "latest"):
                findings.append(finding(
                    "unpinned-version", "error", name,
                    "version spec '%s' floats to whatever is newest at install time" % (spec or "(empty)"), src))
            elif spec.startswith(("^", "~")):
                findings.append(finding(
                    "loose-range", "warning", name,
                    "range '%s' auto-accepts new releases at install time" % spec, src))
    return findings


def check_lockfile(manifest, lock, findings):
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        findings.append(finding("bad-lockfile", "error", "(lockfile)",
                                "package-lock.json has no 'packages' map", "package-lock.json"))
        return findings
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        name = key.split("node_modules/")[-1]
        if entry.get("hasInstallScript"):
            findings.append(finding(
                "install-script", "warning", name,
                "version %s runs install-time scripts (native build or arbitrary code)"
                % entry.get("version", "?"), "package-lock.json"))
        resolved = entry.get("resolved")
        if resolved and not str(resolved).startswith(NPM_REGISTRY_PREFIX):
            findings.append(finding(
                "unknown-tarball-host", "error", name,
                "tarball URL does not come from registry.npmjs.org: %s" % resolved,
                "package-lock.json"))
    # Drift: every registry-sourced manifest dep must exist in the lock, and
    # an exact pin must match the locked version.
    for section in ("dependencies", "devDependencies"):
        deps = manifest.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec = str(spec).strip()
            if spec.startswith(NON_REGISTRY_PREFIXES):
                continue
            locked = packages.get("node_modules/" + name)
            if locked is None:
                findings.append(finding(
                    "lockfile-drift", "error", name,
                    "declared in package.json but missing from package-lock.json"
                    " - install state is not reproducible", "package.json vs package-lock.json"))
            elif spec and not spec.startswith(("^", "~")) and spec not in ("*", "latest"):
                if locked.get("version") != spec:
                    findings.append(finding(
                        "lockfile-drift", "error", name,
                        "package.json pins %s but lockfile resolves %s"
                        % (spec, locked.get("version", "?")),
                        "package.json vs package-lock.json"))
    return findings


def audit(path):
    """Audit the npm project at `path`. Returns a list of findings."""
    findings = []
    manifest = None
    lock = None
    try:
        with open(path.rstrip("/") + "/package.json") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        return [finding("no-manifest", "error", "(project)",
                        "no package.json found at %s" % path, path)]
    except json.JSONDecodeError as e:
        return [finding("bad-manifest", "error", "(project)",
                        "package.json is not valid JSON: %s" % e, path)]
    try:
        with open(path.rstrip("/") + "/package-lock.json") as f:
            lock = json.load(f)
    except FileNotFoundError:
        findings.append(finding(
            "no-lockfile", "warning", "(project)",
            "no package-lock.json - dependency resolution is not pinned", path))
    except json.JSONDecodeError as e:
        findings.append(finding("bad-lockfile", "error", "(lockfile)",
                                "package-lock.json is not valid JSON: %s" % e, path))
    check_manifest(manifest, findings)
    if lock is not None:
        check_lockfile(manifest, lock, findings)
    return findings


def filter_severity(findings, min_severity):
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f["severity"]] >= floor]


def format_text(findings):
    lines = []
    for f in findings:
        lines.append("%-7s %-20s %-28s %s (%s)" % (
            f["severity"].upper(), f["code"], f["package"], f["detail"], f["source"]))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline npm dependency-manifest auditor for agent projects.")
    parser.add_argument("path", nargs="?", default=".",
                        help="project directory containing package.json (default: .)")
    parser.add_argument("--min-severity", choices=["info", "warning", "error"],
                        default="info", help="only report findings at or above this severity")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    findings = filter_severity(audit(args.path), args.min_severity)
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    elif findings:
        print(format_text(findings))
    else:
        print("no findings")
    has_error = any(f["severity"] == "error" for f in findings)
    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
