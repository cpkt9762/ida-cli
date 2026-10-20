"""Release assertions reject broken properties and incomplete creation evidence."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_driver', REPO / 'scripts/verify_nexus_release.py')
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class ReleaseAssertions(unittest.TestCase):
    def test_e27_detects_a_live_recorded_birth(self):
        with self.assertRaisesRegex(AssertionError, 'still live'):
            driver.assert_dead([{'pid': os.getpid(), 'identity': driver.identity(os.getpid())}])

    def test_e28_detects_post_backup_annotation(self):
        with self.assertRaises(AssertionError):
            driver.assert_annotations('POST', 'PRE')

    def test_e29_detects_extra_query_process(self):
        for command in (['ida-cli','serve-worker'], ['/private/idat'], ['ida-nexus','worker']):
            with self.subTest(command=command), self.assertRaises(AssertionError):
                driver.no_query_workers([{'command':command}])
        driver.no_query_workers([{'command':['ida-cli','probe-runtime']}])

    def test_creation_failure_requires_actual_errno_and_no_started_record(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temporary:
            root=Path(temporary)
            ledger=root/'native.jsonl'
            env=SimpleNamespace(root=root,ledger=root/'processes.jsonl',entries=lambda:[])
            intent={'kind':'intent','intent':'one','program':'missing'}
            failed={'kind':'spawn_failed','intent':'one','errno':2,'error':'No such file'}
            ledger.write_text('\n'.join(map(json.dumps,[intent,failed]))+'\n')
            self.assertEqual(driver.capture_native_processes(env,ledger),[])
            for rows in ([intent], [intent,failed|{'errno':None}], [intent,failed,failed]):
                ledger.write_text('\n'.join(map(json.dumps,rows))+'\n')
                with self.assertRaises(AssertionError):driver.capture_native_processes(env,ledger)

    def test_94_comparison_and_missing_release_baseline_are_blocked(self):
        from contextlib import nullcontext
        from unittest.mock import patch
        spec=importlib.util.spec_from_file_location('e2e_driver',REPO/'scripts/verify_nexus_e2e.py')
        e2e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e2e)
        with tempfile.TemporaryDirectory(dir='/private/tmp') as temporary:
            root=Path(temporary)
            (root/'fixtures').mkdir();(root/'fixtures/mini').write_bytes(b'private')
            env=SimpleNamespace(root=root,manifest={'ida_dir':str(root),'installed_ida_version':'9.4'},
                ledger=root/'processes.jsonl',exclusive=lambda:nullcontext(),variables=lambda:{},
                client_patch_status=lambda:{'applied':True,'close_applied':True})
            for suite,extra in [('contract',[]),('release',['--case','E29'])]:
                argv=['verify','--root',str(root),'--target',str(root),'--suite',suite,*extra]
                with patch.object(e2e,'Environment',return_value=env),patch.object(e2e.sys,'argv',argv):
                    with self.assertRaises(SystemExit) as raised:e2e.main()
                    self.assertEqual(raised.exception.code,1)
                result=json.loads((root/f'{suite}-result.json').read_text())
                self.assertEqual(result['status'],'BLOCKED')
                self.assertEqual(result['actual_tests'],0)


if __name__ == '__main__':
    unittest.main()
