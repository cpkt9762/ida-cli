"""A signed LaunchIntent whose owner never existed is settled on exact evidence only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'tests/support')]
from proof_helper import LAUNCH_SETTLE_SECONDS, Observer
from ida_nexus._launch_authorization import create, decide
from target_coordination import Directory, Target
from target_journal import Journal

ACQUISITION = {'parent':'launch-settle', 'purpose':'final', 'ordinal':1}
BRIDGE = {'pid':424242, 'status':'signal: 9 (SIGKILL)', 'exited_secs':float(LAUNCH_SETTLE_SECONDS) + .5}


class LaunchSettle(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ls-', dir=os.environ['R3A_CASE_ROOT']))
        self.storage = Directory(self.root)
        self.addCleanup(self.storage.close)
        self.observer = Observer('launch-settle-helper', 8, storage=self.storage)
        self.target_path = self.root/'tiny.i64'
        self.target_path.write_bytes(b'private input')
        self.suffix = os.urandom(3).hex()
        self.launch = {'suffix':self.suffix, 'source':str(self.target_path),
                       'target':str(self.target_path), 'backend':'idalib'}
        self.launch['authorization'] = create(self.root/'grant.json', self.suffix, str(self.target_path))
        self.children = []
        self.addCleanup(self.reap)

    def reap(self):
        for child in self.children:
            child.kill()
            child.wait(timeout=5)

    def call(self, kind, **fields):
        return self.observer.receive(dict(kind=kind, protocol=2, helper=self.observer.incarnation, **fields))

    def sign_launch(self):
        self.call('reserve_parent', parent=ACQUISITION['parent'])
        with Target(self.target_path) as target:
            with target.locked():
                journal = Journal(target)
                epoch = journal.begin(ACQUISITION, 'startup', launch=self.launch)
                receipt = self.call('launch_intent', watch='startup', subscription_epoch=epoch,
                    target=str(self.target_path), coord_key=target.key, acquisition=ACQUISITION,
                    launch=self.launch)['receipt']
                journal.launch_signed(receipt)
        return epoch

    def fake_worker(self):
        """A private process whose argv carries the launch suffix, like the SDK's worker."""
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', '--managed',
                                  '--record-suffix', self.suffix, '--lease-grace', '20.0'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        self.children.append(child)
        return child

    def test_revocation_needs_no_exec_margin(self):
        self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=dict(BRIDGE, exited_secs=0.0))
        self.assertEqual(reply['state'], 'abandoned')
        self.assertFalse(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))

    def test_absence_after_the_margin_publishes_exact_unspawned_evidence_once(self):
        epoch = self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        self.assertEqual(reply['state'], 'abandoned')
        record = reply['consumer']['record']
        self.assertEqual(record['kind'], 'LaunchAbandonedUnspawned')
        self.assertEqual(record['launch'], self.launch)
        self.assertIsNone(record['owner'])
        self.assertIsNone(record['os_identity'])
        evidence = record['evidence']
        self.assertEqual(evidence['authorization'], self.launch['authorization'])
        self.assertEqual(evidence['decision'], 'revoked')
        self.assertEqual(evidence['bridge'], BRIDGE)
        self.assertTrue(Path(self.launch['authorization'] + '.decision').is_file())
        # ACK loss: repeating the request returns the same immutable fact.
        self.assertEqual(self.call('launch_settle', watch='startup', bridge=BRIDGE), reply)
        self.assertNotIn('proof', self.observer.items['startup'], 'abandonment is never an owner lifetime proof')
        with Target(self.target_path) as target:
            with target.locked():
                journal = Journal(target)
                journal.launch_abandoned({'watch':'startup', 'consumer':reply['consumer']})
                journal.launch_abandoned({'watch':'startup', 'consumer':reply['consumer']})
                item = journal.value['entries'][str(epoch)]
                self.assertIsNone(item['launch'])
                self.assertEqual(item['launch_identity'], self.launch)
                self.assertEqual(item['launch_abandoned']['kind'], 'LaunchAbandonedUnspawned')
                self.assertTrue(item['producer_closed'] and item['consumer_closed'] and item['bridge_closed'])
                self.call('retire', watch='startup', sha256=reply['consumer']['sha256'])
                self.call('retire_parent', parent=ACQUISITION['parent'])
                journal.settle()
                self.assertEqual(journal.value['entries'], {}, 'closed epoch is compacted')
        heartbeat = self.call('heartbeat', summary_only=True)
        self.assertEqual((heartbeat['used'], heartbeat['parent_count']), (0, 0))

    def test_a_worker_with_the_suffix_keeps_the_launch_on_the_public_lifetime_path(self):
        self.sign_launch()
        worker = self.fake_worker()
        self.assertTrue(decide(self.launch['authorization'], self.suffix, str(self.target_path), 'claimed'))
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        self.assertEqual(reply['state'], 'owner_present')
        self.assertEqual(reply['pids'], [])
        self.assertNotIn('consumer', self.observer.items['startup'])
        worker.kill()
        worker.wait(timeout=5)
        self.assertEqual(self.call('launch_settle', watch='startup', bridge=BRIDGE)['state'], 'owner_present',
                         'a claimed launch is retained even after its owner dies; no absence settlement')

    def test_a_known_os_identity_or_discovered_owner_is_not_an_unspawned_launch(self):
        self.sign_launch()
        self.observer.items['startup']['os_identity'] = {'pid':1}
        self.assertEqual(self.call('launch_settle', watch='startup', bridge=BRIDGE), {'state':'not_applicable'})
        self.observer.items['startup'].pop('os_identity')
        self.observer.items['startup']['owner'] = {'record_id':'1-' + self.suffix}
        self.assertEqual(self.call('launch_settle', watch='startup', bridge=BRIDGE), {'state':'not_applicable'})

    def test_malformed_bridge_evidence_is_rejected_before_any_side_effect(self):
        self.sign_launch()
        for bad in ({}, dict(BRIDGE, extra=1), dict(BRIDGE, pid='1'), dict(BRIDGE, exited_secs='9')):
            with self.assertRaisesRegex(ValueError, 'bridge exit evidence'):
                self.call('launch_settle', watch='startup', bridge=bad)
        self.assertNotIn('consumer', self.observer.items['startup'])

    def test_journal_refuses_forged_or_unbound_abandonment(self):
        self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        good = reply['consumer']
        evidence = good['record']['evidence']
        item = self.observer.items['startup']

        def forged(evidence=evidence, **overrides):
            # Genuine immutable facts with content the journal must not accept.
            return self.observer.publish(dict(item, **overrides), 'LaunchAbandonedUnspawned', evidence=evidence)

        def nested(*path, value):
            changed = json.loads(json.dumps(evidence))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            return changed

        cases = {
            'not revoked': forged(nested('decision', value='claimed')),
            'other grant': forged(nested('authorization', value='/invalid/grant')),
            'invalid waitpid age': forged(nested('bridge', 'exited_secs', value=-1.0)),
            'other suffix': forged(nested('suffix', value='other')),
            'birth known': forged(os_identity={'pid':4242}),
            'other launch': forged(launch=dict(self.launch, suffix='other')),
            'no evidence': forged(evidence=None),
        }
        with Target(self.target_path) as target:
            with target.locked():
                journal = Journal(target)
                for name, receipt in cases.items():
                    with self.assertRaises(RuntimeError, msg=name):
                        journal.launch_abandoned({'watch':'startup', 'consumer':receipt})
                with self.assertRaisesRegex(RuntimeError, 'content/identity mismatch'):
                    journal.launch_abandoned({'watch':'startup', 'consumer':dict(good, sha256='0'*64)})
                entry = next(iter(journal.value['entries'].values()))
                self.assertEqual(entry['launch'], self.launch, 'a refused fact leaves the launch pending')
                self.assertNotIn('launch_abandoned', entry)
                journal.launch_abandoned({'watch':'startup', 'consumer':good})
                self.assertIsNone(next(iter(journal.value['entries'].values()))['launch'])

    def test_journal_never_abandons_a_launch_whose_birth_was_signed(self):
        epoch = self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        with Target(self.target_path) as target:
            with target.locked():
                journal = Journal(target)
                journal.value['entries'][str(epoch)]['facts'].append(
                    dict(journal.value['entries'][str(epoch)]['facts'][0], kind='Spawned'))
                with self.assertRaisesRegex(RuntimeError, 'lacks exact unspawned evidence'):
                    journal.launch_abandoned({'watch':'startup', 'consumer':reply['consumer']})

    def test_restart_restores_the_abandonment_fact_as_the_closing_consumer(self):
        self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        restarted = Observer('launch-settle-helper', 8, storage=self.storage)
        self.assertEqual(restarted.items['startup']['consumer'], reply['consumer'])

    def test_legacy_launch_without_authorization_never_settles_from_absence(self):
        self.launch.pop('authorization')
        self.sign_launch()
        reply = self.call('launch_settle', watch='startup', bridge=BRIDGE)
        self.assertEqual(reply['state'], 'not_applicable')
        self.assertNotIn('consumer', self.observer.items['startup'])
        legacy_fact = self.observer.publish(self.observer.items['startup'],
            'LaunchAbandonedUnspawned', evidence={
                'bridge':BRIDGE, 'suffix':self.suffix, 'target':str(self.target_path),
                'settle_seconds':5, 'process_table':{'matches':[]},
                'public_discovery':{'matches':[]}})
        with Target(self.target_path) as target:
            with target.locked():
                journal = Journal(target)
                with self.assertRaisesRegex(RuntimeError, 'lacks exact unspawned evidence'):
                    journal.launch_abandoned({'watch':'startup', 'consumer':legacy_fact})
                self.assertEqual(next(iter(journal.value['entries'].values()))['launch'], self.launch)

    def test_incomplete_decision_preserves_the_obligation(self):
        self.sign_launch()
        Path(self.launch['authorization'] + '.decision').touch(mode=0o600)
        with self.assertRaisesRegex(RuntimeError, 'invalid or incomplete'):
            self.call('launch_settle', watch='startup', bridge=BRIDGE)
        self.assertNotIn('consumer', self.observer.items['startup'])


if __name__ == '__main__':
    unittest.main()
