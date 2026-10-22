import json
import os
import shutil
import tempfile
import unittest

import dep_audit


def write_project(manifest, lock=None):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "package.json"), "w") as f:
        json.dump(manifest, f)
    if lock is not None:
        with open(os.path.join(d, "package-lock.json"), "w") as f:
            json.dump(lock, f)
    return d


def lock_with(entries):
    return {"lockfileVersion": 3, "packages": entries}


CLEAN_MANIFEST = {"name": "ok-app", "dependencies": {"express": "4.21.2"}}
CLEAN_LOCK = lock_with({
    "": {},
    "node_modules/express": {
        "version": "4.21.2",
        "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz",
    },
})


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.dirs = []

    def tearDown(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def project(self, manifest, lock=None):
        d = write_project(manifest, lock)
        self.dirs.append(d)
        return d

    def codes(self, findings):
        return {f["code"] for f in findings}

    def test_clean_project_has_no_findings(self):
        d = self.project(CLEAN_MANIFEST, CLEAN_LOCK)
        self.assertEqual(dep_audit.audit(d), [])

    def test_missing_manifest_is_error(self):
        d = tempfile.mkdtemp()
        self.dirs.append(d)
        findings = dep_audit.audit(d)
        self.assertIn("no-manifest", self.codes(findings))
        self.assertTrue(all(f["severity"] == "error" for f in findings))

    def test_missing_lockfile_warns(self):
        d = self.project(CLEAN_MANIFEST)
        self.assertIn("no-lockfile", self.codes(dep_audit.audit(d)))

    def test_loose_range_warns(self):
        m = {"dependencies": {"express": "^4.21.0"}}
        d = self.project(m, CLEAN_LOCK)
        self.assertIn("loose-range", self.codes(dep_audit.audit(d)))

    def test_star_and_latest_are_errors(self):
        for spec in ("*", "latest"):
            m = {"dependencies": {"express": spec}}
            d = self.project(m, CLEAN_LOCK)
            findings = dep_audit.audit(d)
            self.assertIn("unpinned-version", self.codes(findings))
            err = [f for f in findings if f["code"] == "unpinned-version"][0]
            self.assertEqual(err["severity"], "error")

    def test_exact_pin_has_no_range_finding(self):
        d = self.project(CLEAN_MANIFEST, CLEAN_LOCK)
        self.assertNotIn("loose-range", self.codes(dep_audit.audit(d)))
        self.assertNotIn("unpinned-version", self.codes(dep_audit.audit(d)))

    def test_non_registry_source(self):
        m = {"dependencies": {"my-lib": "git+https://example.com/my-lib.git"}}
        d = self.project(m, CLEAN_LOCK)
        self.assertIn("non-registry-source", self.codes(dep_audit.audit(d)))

    def test_install_script_from_lockfile(self):
        lock = lock_with({
            "": {},
            "node_modules/express": {"version": "4.21.2"},
            "node_modules/evil-native": {"version": "1.0.0", "hasInstallScript": True},
        })
        d = self.project(CLEAN_MANIFEST, lock)
        findings = dep_audit.audit(d)
        self.assertIn("install-script", self.codes(findings))
        hit = [f for f in findings if f["code"] == "install-script"][0]
        self.assertEqual(hit["package"], "evil-native")

    def test_unknown_tarball_host(self):
        lock = lock_with({
            "": {},
            "node_modules/express": {
                "version": "4.21.2",
                "resolved": "https://mirrors.example.com/express-4.21.2.tgz",
            },
        })
        d = self.project(CLEAN_MANIFEST, lock)
        findings = dep_audit.audit(d)
        self.assertIn("unknown-tarball-host", self.codes(findings))
        self.assertTrue(any(f["severity"] == "error" for f in findings))

    def test_lockfile_drift_missing_entry(self):
        m = {"dependencies": {"express": "4.21.2", "ghost-dep": "1.0.0"}}
        d = self.project(m, CLEAN_LOCK)
        findings = dep_audit.audit(d)
        drift = [f for f in findings if f["code"] == "lockfile-drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["package"], "ghost-dep")

    def test_lockfile_drift_version_mismatch(self):
        lock = lock_with({"": {}, "node_modules/express": {"version": "4.21.1"}})
        d = self.project(CLEAN_MANIFEST, lock)
        findings = dep_audit.audit(d)
        self.assertIn("lockfile-drift", self.codes(findings))

    def test_typosquat_one_edit_is_error(self):
        m = {"dependencies": {"my-sdk": "1.0.0"}}  # not proximate to any target
        d = self.project(m, lock_with({"": {}, "node_modules/my-sdk": {"version": "1.0.0"}}))
        self.assertNotIn("typosquat-risk", self.codes(dep_audit.audit(d)))
        m2 = {"dependencies": {"1itellm": "1.107.0"}}  # 1 edit from litellm
        d2 = self.project(m2, lock_with({"": {}, "node_modules/1itellm": {"version": "1.107.0"}}))
        findings = dep_audit.audit(d2)
        typo = [f for f in findings if f["code"] == "typosquat-risk"]
        self.assertEqual(len(typo), 1)
        self.assertEqual(typo[0]["severity"], "error")

    def test_typosquat_two_edits_is_warning(self):
        m = {"dependencies": {"1itel1m": "1.0.0"}}  # 2 edits from litellm
        d = self.project(m, lock_with({"": {}, "node_modules/1itel1m": {"version": "1.0.0"}}))
        findings = dep_audit.audit(d)
        typo = [f for f in findings if f["code"] == "typosquat-risk"]
        self.assertEqual(len(typo), 1)
        self.assertEqual(typo[0]["severity"], "warning")

    def test_exact_target_name_not_flagged(self):
        m = {"dependencies": {"litellm": "1.107.1"}}
        d = self.project(m, lock_with({"": {}, "node_modules/litellm": {"version": "1.107.1"}}))
        self.assertNotIn("typosquat-risk", self.codes(dep_audit.audit(d)))

    def test_confusable_name(self):
        m = {"dependencies": {"rеquests": "1.0.0"}}  # cyrillic е
        d = self.project(m, lock_with({"": {}, "node_modules/реquests": {"version": "1.0.0"}}))
        self.assertIn("confusable-name", self.codes(dep_audit.audit(d)))

    def test_levenshtein(self):
        self.assertEqual(dep_audit.levenshtein("abc", "abc"), 0)
        self.assertEqual(dep_audit.levenshtein("abc", "abd"), 1)
        self.assertEqual(dep_audit.levenshtein("", "ab"), 2)
        self.assertEqual(dep_audit.levenshtein("kitten", "sitting"), 3)

    def test_min_severity_filter(self):
        m = {"dependencies": {"express": "^4.21.0", "1itellm": "1.0.0"}}
        lock = lock_with({"": {}, "node_modules/express": {"version": "4.21.2"},
                          "node_modules/1itellm": {"version": "1.0.0"}})
        d = self.project(m, lock)
        warnings_up = dep_audit.filter_severity(dep_audit.audit(d), "warning")
        self.assertIn("loose-range", self.codes(warnings_up))
        errors_only = dep_audit.filter_severity(dep_audit.audit(d), "error")
        self.assertNotIn("loose-range", self.codes(errors_only))
        self.assertIn("typosquat-risk", self.codes(errors_only))

    def test_bad_json_manifest(self):
        d = tempfile.mkdtemp()
        self.dirs.append(d)
        with open(os.path.join(d, "package.json"), "w") as f:
            f.write("{not json")
        self.assertIn("bad-manifest", self.codes(dep_audit.audit(d)))

    def test_bad_lockfile_shape(self):
        d = self.project(CLEAN_MANIFEST, {"lockfileVersion": 3})
        findings = dep_audit.audit(d)
        self.assertIn("bad-lockfile", self.codes(findings))

    def test_cli_exit_codes(self):
        clean = self.project(CLEAN_MANIFEST, CLEAN_LOCK)
        self.assertEqual(dep_audit.main([clean]), 0)
        dirty = self.project({"dependencies": {"express": "*"}}, CLEAN_LOCK)
        self.assertEqual(dep_audit.main([dirty]), 1)

    def test_cli_json_format(self):
        import io
        from contextlib import redirect_stdout
        d = self.project({"dependencies": {"express": "*"}}, CLEAN_LOCK)
        buf = io.StringIO()
        with redirect_stdout(buf):
            dep_audit.main([d, "--format", "json"])
        parsed = json.loads(buf.getvalue())
        self.assertTrue(any(f["code"] == "unpinned-version" for f in parsed))

    def test_dev_dependencies_scanned(self):
        m = {"devDependencies": {"esbuild": "^0.20.0"}}
        lock = lock_with({"": {}, "node_modules/esbuild": {"version": "0.20.2"}})
        d = self.project(m, lock)
        self.assertIn("loose-range", self.codes(dep_audit.audit(d)))


if __name__ == "__main__":
    unittest.main()
