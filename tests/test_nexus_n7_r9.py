"""Missing-metadata evidence preserves raw values and excludes credentials."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('n7_metadata', Path(__file__).resolve().parents[1]/'nexus_bridge/metadata.py')
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)


class MetadataEvidence(unittest.TestCase):
    def test_missing_values_owner_identity_and_disk_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'copy.i64'
            path.write_bytes(b'packed test bytes')
            before = metadata.idb_fingerprint(path)
            instance = types.SimpleNamespace(record_id='owner-1', pid=123,
                idb_path=str(path), token='NEVER_LOG_TOKEN')
            discovered = types.SimpleNamespace(instance=instance, state=types.SimpleNamespace(value='ready'))
            modules = {
                'ida_loader': types.SimpleNamespace(PATH_TYPE_IDB=0, get_path=lambda _: str(path)),
                'ida_nalt': types.SimpleNamespace(get_input_file_path=lambda: '', get_root_filename=lambda: '',
                    retrieve_input_file_size=lambda: 0, retrieve_input_file_md5=lambda: None,
                    retrieve_input_file_sha256=lambda: None),
                'ida_auto': types.SimpleNamespace(auto_is_ok=lambda: True, get_auto_state=lambda: 0),
                'ida_nexus': types.SimpleNamespace(discover_databases=lambda **_: [discovered]),
            }
            with patch.dict(sys.modules, modules), self.assertLogs('ida_cli.metadata', level='WARNING') as logs:
                metadata.warn_missing_input_metadata({'input_file_path':'', 'input_file_size':0,
                    'md5':'0'*32, 'sha256':'0'*64}, {'requested_path':str(path),
                    'record_id':'owner-1', 'before_open':before, 'forensic_hash':True})
            text = logs.output[0].split('missing input metadata: ', 1)[1]
            evidence = json.loads(text)
            self.assertNotIn('NEVER_LOG_TOKEN', text)
            self.assertEqual(evidence['before_open'], before)
            self.assertEqual(evidence['disk_now'], before)
            self.assertEqual(evidence['actual_idb_path'], str(path))
            self.assertEqual(evidence['record_id'], 'owner-1')
            self.assertEqual(evidence['raw']['retrieve_input_file_sha256'], {'type':'NoneType', 'value':None})
            self.assertEqual(path.read_bytes(), b'packed test bytes')

    def test_healthy_metadata_does_not_probe_or_log(self):
        with patch.object(metadata, 'input_metadata_evidence', side_effect=AssertionError('unexpected probe')):
            metadata.warn_missing_input_metadata({'input_file_path':'source', 'input_file_size':1,
                'md5':'1'*32, 'sha256':'2'*64})

    def test_disk_absence_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            result = metadata.idb_fingerprint(Path(directory)/'missing.i64')
            self.assertEqual(result['error'], 'FileNotFoundError')
            self.assertNotIn('sha256', result)


if __name__ == '__main__':
    unittest.main()
