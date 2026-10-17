"""Exercise the bootstrap from an installed private layout, never the source tree."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ["R0_CASE_ROOT"]).resolve()
ROOT.mkdir(mode=0o700, parents=True)


class InstallPrototype(unittest.TestCase):
    def test_clean_launcher_excludes_prestartup_injection_all_modes(self):
        install = ROOT / "install"
        install.mkdir(mode=0o700)
        evil = ROOT / "evil"
        evil.mkdir()
        sentinel = evil / "EXECUTED"
        code = f"open({str(sentinel)!r}, 'w').write('loaded')\n"
        (evil / "sitecustomize.py").write_text(code)
        (evil / "r0_maintenance_payload.py").write_text(code)
        for source in (REPO / "nexus_bridge").glob("*.py"):
            shutil.copyfile(source, install / source.name)
        shutil.copyfile(REPO / "scripts/nexus/r0_bootstrap.py", install / "r0_bootstrap.py")
        (install / "r0_maintenance_payload.py").write_text("import open_recovery\n")
        manifest = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in install.glob("*.py")}
        (install / "manifest.json").write_text(json.dumps(manifest))
        # Positive challenge: the malicious startup hook executes without the launcher.
        challenge = subprocess.run(["timeout", "30s", sys.executable, "-c", "pass"], cwd=evil,
                                   env=dict(os.environ, PYTHONPATH=str(evil)), capture_output=True)
        self.assertEqual(challenge.returncode, 0)
        self.assertTrue(sentinel.exists())
        sentinel.unlink()
        results = []
        for mode in ("ordinary", "isolated", "safe", "envsafe"):
            command = ["timeout", "30s", "sh", str(REPO / "scripts/nexus/r0_maintenance_launch.sh"),
                       sys.executable, str(install), mode, "--help"]
            result = subprocess.run(command, cwd=evil, env={"PATH":os.environ["PATH"],
                                    "PYTHONPATH":str(evil), "PYTHONHOME":str(evil)},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["source"], str(install / "r0_maintenance_payload.py"))
            self.assertFalse(sentinel.exists(), "sitecustomize must be excluded BEFORE interpreter startup")
            results.append({"mode":mode, "argv":command, "exit":result.returncode})
        (install / "r0_maintenance_payload.py").write_text("raise RuntimeError('tampered')")
        result = subprocess.run(command, cwd=evil, env={"PATH":os.environ["PATH"]}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest mismatch", result.stderr)
        (ROOT / "install-results.json").write_text(json.dumps({"cases":results, "tamper_rejected":True,
                      "application_maintenance":"NotImplemented-in-R0", "production_module_imported":"open_recovery"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
