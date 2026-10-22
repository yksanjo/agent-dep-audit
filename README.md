# agent-dep-audit

Offline supply-chain auditor for an agent project's npm manifests.

Agents install dependencies, and dependency manifests are an attack surface: typosquatted names, floating version specs, install-time scripts, tarballs from unknown hosts, and lockfiles that silently drifted from the manifest. This tool scans `package.json` and `package-lock.json` for those signals and reports findings with severity. It never touches the network, never installs anything, and cannot block an install. It is a heuristic scanner, not a vulnerability feed.

## What it reports

| Code | Severity | Signal |
| --- | --- | --- |
| `typosquat-risk` | error (1 edit) / warning (2 edits) | dependency name within edit distance 1-2 of a high-value package (litellm, openai, requests, express, ...) |
| `unpinned-version` | error | version spec `*`, `latest`, or empty floats to whatever is newest at install time |
| `lockfile-drift` | error | manifest dep missing from the lockfile, or an exact pin that does not match the locked version |
| `unknown-tarball-host` | error | lockfile `resolved` URL outside registry.npmjs.org |
| `loose-range` | warning | `^` / `~` range auto-accepts new releases at install time |
| `non-registry-source` | warning | dependency resolves from git, file, link, or a URL instead of the registry |
| `install-script` | warning | locked package runs install-time scripts |
| `confusable-name` | warning | package name contains non-ASCII characters (homoglyph risk) |
| `no-lockfile` | warning | no package-lock.json, so resolution is not pinned |
| `no-manifest` / `bad-manifest` / `bad-lockfile` | error | inputs missing or malformed |

## Usage

```bash
python3 dep_audit.py /path/to/project
python3 dep_audit.py . --min-severity warning
python3 dep_audit.py . --format json
python3 demo.py
python3 -m unittest test_dep_audit
```

Exit code is 1 when any reported finding is an error, else 0, so it can gate CI.

## Why offline

A supply-chain scanner that phones home to check packages is itself part of the supply chain. Everything here is computed from the two manifest files: edit distance, spec parsing, lockfile cross-checks. No registry calls, no telemetry, no model.

## Honest limits

- Heuristics, not a CVE feed. It knows nothing about specific published vulnerabilities; it flags shapes that correlate with compromise. A clean result is not a guarantee of safety.
- Typosquat detection uses a small built-in target list and Levenshtein distance. It produces false positives (short names, legitimate forks) and false negatives (squats of packages not in the list).
- Install scripts are flagged by presence, not content. Many are legitimate native builds (esbuild, better-sqlite3).
- npm manifests only. Python (requirements.txt / pyproject.toml) and other ecosystems are not scanned.
- Non-registry dependencies (git, file) cannot be cross-checked against the lockfile and are only flagged for their source.
- Demo fixtures are synthetic and invented.

## License

MIT
