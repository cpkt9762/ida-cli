"""Independent production writers, real Target EX, synthetic interrupted epochs.

Completed epoch flags and the reference manifest are controlled file inputs,
not claims of N1/helper/public-owner proof. All private scenes are retained.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
INSTALL = Path(os.environ.get('R3A_INSTALLATION', REPO / 'nexus_bridge/custody'))
sys.path[:0] = [str(INSTALL), str(REPO / 'nexus_bridge')]
from target_coordination import Target
from target_journal import Journal, verification_scope
from owner_identity import state_identity

PARENT = dict(client_id='writer-check', request_id='writer-check', operation_id='writer-check', task_id=None)


class WriterAuthorization(unittest.TestCase):
    def prepare(self, variant):
        root = Path(tempfile.mkdtemp(prefix=variant+'-', dir=os.environ['R3A_CASE_ROOT']))
        root.chmod(0o700)
        (root/'copy').mkdir(mode=0o700)
        probe = root / 'copy/probe.i64'
        shutil.copyfile(os.environ['R3F1_SAMPLE'], probe)
        probe.chmod(0o600)
        (probe.parent/'input').write_bytes(b'private input')
        with Target(probe) as target, target.locked():
            verification_scope(target, PARENT)
            journal = Journal(target)
            epoch = journal.begin(dict(parent=PARENT, purpose='verification', ordinal=1), 'writer-watch')
            container = target.directory.child('observations')
            producer = container.child('controlled-reference')
            producer.durable('reference.json', {'controlled': 'immutable manifest boundary'})
            reference = producer.path/'reference.json'
            info = reference.stat()
            item = journal.value['entries'][str(epoch)]
            item['facts'] = [dict(path=str(reference), sha256=hashlib.sha256(reference.read_bytes()).hexdigest(),
                                 inode=[info.st_dev, info.st_ino], kind='controlled-boundary')]
            producer.close(); container.close()
            item.update(producer_closed=True, consumer_closed=True, detached=True,
                        bridge_closed=True, unacked_events=False)
            with patch.object(Journal, 'resume_compaction', side_effect=RuntimeError('controlled interruption')):
                with self.assertRaisesRegex(RuntimeError, 'controlled interruption'):
                    journal.settle()
            value, _, _ = target.directory.read('custody.json')
            if variant == 'missing': value.pop('verification_scope')
            elif variant == 'foreign-parent': value['verification_scope']['parent']['operation_id'] = 'foreign'
            elif variant == 'sticky-conflict': value['verification_cleanup_conflict'] = True
            elif variant == 'null': value['verification_scope'] = None
            target.directory.durable('custody.json', value)
            journal_path = target.directory.path/'custody.json'
            if variant == 'corrupt': journal_path.write_bytes(b'{corrupt journal')
            before = journal_path.read_bytes()
            key = target.key
        (root/'before.json').write_bytes(before)
        return root, probe, journal_path, reference, key, before

    def writer(self, variant, action):
        root, probe, journal, reference, key, before = self.prepare(variant)
        payload = probe.read_bytes(); immutable = reference.read_bytes()
        request = dict(action=action, target=str(probe), coord_key=key,
                       state_root=state_identity(), parent=PARENT)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(INSTALL), str(REPO/'nexus_bridge')]))
        result = subprocess.run(['timeout', '10s', sys.executable, '-B', str(INSTALL/'target_journal.py')],
                                input=json.dumps(request)+'\n', text=True, capture_output=True, env=env, check=False)
        (root/'writer.stdout').write_text(result.stdout); (root/'writer.stderr').write_text(result.stderr)
        after = journal.read_bytes(); (root/'after.json').write_bytes(after)
        evidence = dict(variant=variant, action=action, exit=result.returncode,
                        journal_unchanged=before==after, reference_retained=reference.exists(),
                        payload_retained=probe.exists(), scope='actual independent writer/EX; synthetic epoch/manifest')
        (root/'result.json').write_text(json.dumps(evidence, indent=2))
        return result, probe, reference, payload, immutable, before, after

    def test_rejected_cleanup_preserves_journal_payload_and_reference(self):
        for variant in ('missing', 'foreign-parent', 'sticky-conflict', 'null', 'corrupt'):
            with self.subTest(variant=variant):
                result, probe, reference, payload, immutable, before, after = self.writer(variant, 'verification_probe_cleanup')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('JSONDecodeError' if variant=='corrupt' else 'VerificationCleanupBlocked', result.stderr)
                self.assertEqual(after, before, 'authorization refusal must precede any recovery write')
                self.assertEqual(probe.read_bytes(), payload)
                self.assertEqual(reference.read_bytes(), immutable, 'refusal must precede manifest unlink')

    def test_ordinary_writer_still_recovers_compaction(self):
        result, probe, reference, payload, _, before, after = self.writer('ordinary', 'accounting')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(before, after)
        self.assertFalse(reference.exists())
        self.assertEqual(probe.read_bytes(), payload)

    def test_authorized_cleanup_recovers_then_removes_only_payload(self):
        result, probe, reference, _, _, before, after = self.writer('legal', 'verification_probe_cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertNotEqual(before, after)
        self.assertFalse(reference.exists())
        self.assertFalse(probe.exists())
        self.assertTrue((probe.parent/'input').is_file())
        self.assertTrue((probe.parent/'closed').is_file())


class ClosedObservations(unittest.TestCase):
    """Writer-side contract only; terminal flags and proof digest are synthetic."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='closed-observation-', dir=os.environ['R3A_CASE_ROOT']))
        self.probe = self.root/'probe.i64'
        shutil.copyfile(os.environ['R3F1_SAMPLE'], self.probe)
        self.lease = dict(client_id='writer-check', lease_id='exact-lease', instance_id='exact-owner', generation=1, owner='headless')
        self.owner = dict(record_id='exact-owner')
        self.acquisition = dict(parent=PARENT, purpose='final', ordinal=1)
        with Target(self.probe) as target, target.locked():
            journal = Journal(target)
            self.epoch = journal.begin(self.acquisition, 'exact-watch', owner=self.owner)
            item = journal.value['entries'][str(self.epoch)]
            item.update(lease=self.lease, proof={'sha256':'1'*64}, producer_closed=True,
                        consumer_closed=True, detached=True, bridge_closed=True, unacked_events=False)
            journal.settle()
            self.assertEqual(journal.value['entries'], {})
            self.journal = target.directory.path/'custody.json'
            self.request = dict(action='release_observation', target=str(self.probe), coord_key=target.key,
                lease=self.lease, owner=self.owner, watch='exact-watch', epoch=self.epoch,
                acquisition=self.acquisition, observation_id='same-nonce',
                attempt=dict(sequence=1, target=dict(kind='release', lease=self.lease)),
                outcome=dict(stage='preflight', detach_called=False, cause=dict(type='RuntimeError', message='original')))

    def write(self, value):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(INSTALL), str(REPO/'nexus_bridge')]))
        result = subprocess.run(['timeout', '10s', sys.executable, '-B', str(INSTALL/'target_journal.py')],
            input=json.dumps(value)+'\n', text=True, capture_output=True, env=env, check=False)
        with (self.root/'writer-results.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(request=value, exit=result.returncode, stdout=result.stdout, stderr=result.stderr))+'\n')
        return result

    def test_exact_closed_observation_is_idempotent_and_conflicts_refuse(self):
        import copy
        self.assertEqual(self.write(self.request).returncode, 0)
        before = self.journal.read_bytes()
        self.assertEqual(self.write(self.request).returncode, 0)
        self.assertEqual(self.journal.read_bytes(), before)
        for variant in ('nonce-conflict', 'different-attempt', 'old-ordinal', 'wrong-watch', 'wrong-generation'):
            with self.subTest(variant=variant):
                value = copy.deepcopy(self.request)
                if variant=='nonce-conflict':value['outcome']['cause']['message']='conflicting'
                elif variant=='different-attempt':value['observation_id']='different-nonce'
                elif variant=='old-ordinal':value['acquisition']['ordinal']=2
                elif variant=='wrong-watch':value['watch']='other-watch'
                else:
                    value['lease']['generation']=2
                    value['attempt']['target']['lease']=value['lease']
                self.assertEqual(self.write(value).returncode, 1)
                self.assertEqual(self.journal.read_bytes(), before)

    def test_old_summary_and_byte_pressure_never_upgrade_authority(self):
        import copy
        before = self.journal.read_bytes()
        pressure = copy.deepcopy(self.request)
        pressure['outcome']['pressure']='x'*17000
        result = self.write(pressure)
        self.assertEqual(result.returncode, 1)
        self.assertIn('RetainedEvidenceFull', result.stderr)
        self.assertEqual(self.journal.read_bytes(), before)
        with Target(self.probe) as target, target.locked():
            journal = Journal(target)
            journal.value['summary'][0].pop('release_binding')
            journal.save()
        before = self.journal.read_bytes()
        result = self.write(self.request)
        self.assertEqual(result.returncode, 1)
        self.assertIn('exact closed release binding missing', result.stderr)
        self.assertEqual(self.journal.read_bytes(), before)
