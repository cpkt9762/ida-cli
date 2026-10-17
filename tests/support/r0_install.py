"""Exercise the bootstrap from an installed private layout, never the source tree."""
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ["R0_CASE_ROOT"]).resolve()
ROOT.mkdir(mode=0o700, parents=True)


class InstallPrototype(unittest.TestCase):
    def layout(self, folder):
        folder.mkdir(mode=0o700)
        for source in (REPO / "nexus_bridge").glob("*.py"):
            shutil.copyfile(source, folder / source.name)
        shutil.copyfile(REPO / "scripts/nexus/r0_bootstrap.py", folder / "r0_bootstrap.py")
        (folder / "r0_maintenance_payload.py").write_text("import open_recovery\n")
        self.manifest(folder)
        return folder

    def manifest(self, install):
        value = {"schema":1, "files":{p.name:{"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),
            "mode":p.stat().st_mode & 0o777} for p in install.glob("*.py")}}
        (install / "manifest.json").write_text(json.dumps(value))
        return value

    def test_manifest_closure_permissions_and_bytecode_rejected(self):
        results = []
        for case in ("omitted-payload", "omitted-dependency", "schema", "permissions",
                     "declared-writable", "stale-pyc", "symlink", "extra-module"):
            with self.subTest(case=case):
                install = self.layout(ROOT / case)
                payload = install / "r0_maintenance_payload.py"
                sentinel = install / "EXECUTED"
                evil = "from pathlib import Path\nPath(__file__).with_name('EXECUTED').touch()\n"
                if case in ("omitted-payload", "permissions", "declared-writable"):
                    payload.write_text(evil)
                value = self.manifest(install)
                if case == "omitted-payload":
                    del value["files"][payload.name]
                    payload.chmod(0o666)
                elif case == "omitted-dependency":
                    del value["files"]["open_recovery.py"]
                elif case == "schema":
                    value["schema"] = 2
                elif case == "permissions":
                    payload.chmod(0o666)
                elif case == "declared-writable":
                    payload.chmod(0o666)
                    value["files"][payload.name]["mode"] = 0o666
                elif case == "stale-pyc":
                    pyc = Path(importlib.util.cache_from_source(str(payload)))
                    pyc.parent.mkdir()
                    info = payload.stat()
                    pyc.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack("<III", 0,
                        int(info.st_mtime), info.st_size) + marshal.dumps(compile(evil, str(payload), "exec")))
                    self.assertEqual(value["files"][payload.name]["sha256"], hashlib.sha256(payload.read_bytes()).hexdigest())
                elif case == "symlink":
                    copy = install / "payload-copy"
                    payload.rename(copy)
                    payload.symlink_to(copy)
                else:
                    (install / "unlisted.py").write_text(evil)
                (install / "manifest.json").write_text(json.dumps(value))
                # Matching timestamp/size pyc is rejected, independent of -B.
                result = subprocess.run(["timeout", "30s", "sh", str(REPO / "scripts/nexus/r0_maintenance_launch.sh"),
                    sys.executable, str(install), "isolated", "--help"],
                    cwd=ROOT, env={"PATH":os.environ["PATH"]}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, case)
                self.assertFalse(sentinel.exists(), case)
                results.append({"case":case,"exit":result.returncode,"sentinel_executed":False,
                                "rejection":result.stderr.splitlines()[-1]})
        (ROOT / "install-rejections.json").write_text(json.dumps(results))

    def test_clean_launcher_excludes_prestartup_injection_all_modes(self):
        install = self.layout(ROOT / "install")
        evil = ROOT / "evil"
        evil.mkdir()
        sentinel = evil / "EXECUTED"
        code = f"open({str(sentinel)!r}, 'w').write('loaded')\n"
        (evil / "sitecustomize.py").write_text(code)
        (evil / "r0_maintenance_payload.py").write_text(code)
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
            self.assertEqual(json.loads(result.stdout)["execution"], "verified-source-bytes")
            self.assertEqual(len(json.loads(result.stdout)["manifest_members"]), 16)
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
