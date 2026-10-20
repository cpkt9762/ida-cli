"""Removed configuration is rejected locally, before even daemon discovery."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REMOVED = ('IDA_CLI_NEXUS_DEV', 'IDA_CLI_WORKER_BACKEND', 'IDA_CLI_MAX_WORKERS',
           'IDA_CLI_MAX_WORKERS_PER_TENANT', 'IDA_CLI_MAX_PENDING_PER_WORKER',
           'IDA_CLI_MAX_CONCURRENT_SPAWNS', 'IDA_CLI_SDK_VERSION')


class RemovedConfigurationTests(unittest.TestCase):
    def test_every_removed_variable_including_empty_is_rejected_before_cli(self):
        binary = os.environ['N9_PROBE_BINARY']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base = {k: v for k, v in os.environ.items() if k not in REMOVED}
            base.update(HOME=str(root), IDA_CLI_HOME=str(root / 'cli'))
            for name in REMOVED:
                for value in ('', '1'):
                    # --help used to exit successfully. The configuration error
                    # must precede clap, logging, socket discovery and autostart.
                    commands = [['--help'], ['status']]
                    if name in REMOVED[:2]:
                        commands += [['serve'], ['serve-http'], ['probe-runtime']]
                    for command in commands:
                        with self.subTest(name=name, value=value, command=command):
                            result = subprocess.run([binary, *command], env=base | {name: value},
                                capture_output=True, text=True, timeout=5)
                            self.assertNotEqual(result.returncode, 0, result.stdout)
                            self.assertIn(name, result.stderr)
                            self.assertIn('removed', result.stderr)
                            self.assertIn('Nexus', result.stderr)
            self.assertFalse((root / 'cli').exists(), 'reject before any state/log initialization')


if __name__ == '__main__':
    unittest.main()
