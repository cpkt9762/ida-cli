"""Review boundaries: real public lifetime, precise admission and durable producers."""
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'tests/support'), str(REPO/'nexus_bridge')]
from acquisition import Custodian
from bridge_observer import BackupSources
from bridge import Bridge, SLICE_GATE_SOURCES
from owner_identity import owner_key, state_identity
from proof_helper import Observer
from r0_transport import Boundary
from target_coordination import Directory, LIMIT, RESERVE, Target
from target_journal import Journal


def until(check):
    end = time.monotonic()+4
    while True:
        value = check()
        if value:
            return value
        assert time.monotonic() < end, 'exact private barrier deadline'
        threading.Event().wait(.005)


class CustodyFix1(unittest.TestCase):
    def test_restart_resumes_only_pending_copy_of_committed_registry(self):
        for conflict in (False, True):
            with self.subTest(conflict=conflict):
                path = (self.root/str(conflict)).resolve()
                path.mkdir(mode=0o700)
                directory = Directory(path)
                try:
                    observer = Observer('registry-restart', 8, storage=directory)
                    saved, _, _ = directory.read('helper-state.json')
                    pending = dict(saved, seq=1) if conflict else saved
                    with patch('target_coordination.os.replace', side_effect=OSError(errno.EIO, 'private registry pre-commit crash')):
                        with self.assertRaises(OSError):
                            directory.durable('helper-state.json', pending)
                    if conflict:
                        with self.assertRaisesRegex(RuntimeError, 'partial content conflict'):
                            Observer(observer.incarnation, 8, storage=directory)
                        self.assertTrue((path/'helper-state.json.new').exists())
                    else:
                        recovered = Observer(observer.incarnation, 8, storage=directory)
                        self.assertTrue(recovered.recovered)
                        self.assertFalse((path/'helper-state.json.new').exists())
                        self.assertEqual(directory.read('helper-state.json')[0], saved)
                finally:
                    directory.close()

    def test_owner_slice_auxiliary_attach_checks_private_target_gate(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('private_slices', REPO/'nexus_bridge/slices.py')
        slices = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(slices)
        slices._target_gate_sources = SLICE_GATE_SOURCES
        with Boundary(self.root/'slice', stub_ida=False) as boundary:
            calls = []
            with patch('ida_nexus.DatabaseHandle.attach', side_effect=lambda instance:calls.append(instance) or 'attached'):
                self.assertEqual(slices.attach_cleanup(boundary.instance), 'attached')
                self.assertEqual(calls, [boundary.instance])
                with Target(boundary.path) as target:
                    with target.locked():
                        target.directory.durable('custody.json', {'broken':True})
                with self.assertRaisesRegex(RuntimeError, 'CoordinationBlocked'):
                    slices.attach_cleanup(boundary.instance)
                self.assertEqual(calls, [boundary.instance])

    def test_owner_slice_gate_has_a_closed_import_chain_without_repo_sys_path(self):
        import builtins
        import importlib.util
        spec = importlib.util.spec_from_file_location('isolated_slices', REPO/'nexus_bridge/slices.py')
        slices = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(slices)
        slices._target_gate_sources = SLICE_GATE_SOURCES
        original = builtins.__import__
        def external_import(name, *args, **kwargs):
            if name == 'process_timeout':
                raise ModuleNotFoundError('process_timeout is unavailable outside the closed owner source bundle')
            return original(name, *args, **kwargs)
        with Boundary(self.root/'closed-slice', stub_ida=False) as boundary, \
                patch('builtins.__import__', side_effect=external_import), \
                patch('ida_nexus.DatabaseHandle.attach', return_value='attached') as attached:
            self.assertEqual(slices.attach_cleanup(boundary.instance),'attached')
            attached.assert_called_once_with(boundary.instance)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='fix-', dir=os.environ['R3A_CASE_ROOT']))
        self.observers = []

    def tearDown(self):
        for observer in self.observers:
            with observer.lock:
                entries = list(observer.owners.values())
                for entry in entries:
                    entry['stop'].set()
            for entry in entries:
                entry.get('thread') and entry['thread'].join(2)
                self.assertFalse(entry.get('thread') and entry['thread'].is_alive())

    def observer(self, name):
        observer = Observer(name, 8)
        self.observers.append(observer)
        return observer

    def subscribe(self, observer, boundary, watch='watch'):
        acquisition = {'parent':{'operation_id':'parent'}, 'purpose':'final', 'ordinal':1}
        owner = owner_key(boundary.instance)
        observer.receive(dict(kind='reserve_parent', protocol=2, helper=observer.incarnation,
                              parent=acquisition['parent']))
        with Target(boundary.path) as target:
            with target.locked():
                epoch = Journal(target).begin(acquisition, watch, owner=owner)
                value = dict(watch=watch, target=str(boundary.path), coord_key=target.key,
                             acquisition=acquisition, owner=owner, subscription_epoch=epoch)
                receipt = observer.receive(dict(value, kind='subscribe', protocol=2,
                                                helper=observer.incarnation))['receipt']
                Journal(target).owner_signed(receipt)
        return value

    def test_true_proof_retries_partial_write_commit_and_registry_without_new_identity(self):
        for fault in ('partial-write', 'committed-before-return', 'registry-after-proof'):
            with self.subTest(fault=fault), Boundary(self.root/fault, stub_ida=False) as boundary:
                observer = self.observer('retry-'+fault)
                value = self.subscribe(observer, boundary)
                item = observer.items[value['watch']]
                failed = threading.Event()
                original = Directory.retry_immutable
                persist = observer.persist
                identities = []
                def write(directory, name, record, **kwargs):
                    if record.get('kind') != 'PublicOwnerLifetime':
                        return original(directory, name, record, **kwargs)
                    identities.append(record['observation_id'])
                    if not failed.is_set() and fault == 'partial-write':
                        raw_write = os.write
                        count = [0]
                        def partial(fd, data):
                            count[0] += 1
                            if count[0] == 1:
                                return raw_write(fd, data[:17])
                            failed.set()
                            raise OSError(errno.ENOSPC, 'private one-shot partial proof write')
                        with patch('target_coordination.os.write', side_effect=partial):
                            return original(directory, name, record, **kwargs)
                    result = original(directory, name, record, **kwargs)
                    if not failed.is_set() and fault == 'committed-before-return':
                        failed.set()
                        raise OSError(errno.EIO, 'private commit-before-registry error')
                    return result
                def registry():
                    if fault == 'registry-after-proof' and item.get('proof') and not failed.is_set():
                        failed.set()
                        raise OSError(errno.EIO, 'private registry failure after proof')
                    return persist()
                with patch.object(Directory, 'retry_immutable', write), patch.object(observer, 'persist', registry):
                    boundary.release_owner()
                    until(failed.is_set)
                    until(lambda: item.get('proof') and not next(iter(observer.owners.values()))['started'])
                proof = item['proof']
                self.assertEqual(len(set(identities)), 1, 'retry allocated a second proof identity')
                self.assertEqual(len(list(Path(proof['path']).parent.glob('*.json'))), 1)
                self.assertEqual(list(Path(proof['path']).parent.glob('*.new')), [])
                self.assertEqual(item.get('pending_facts'), {})
                with Target(boundary.path) as target:
                    with target.locked():
                        Journal(target).proof({'watch':value['watch'], 'proof':proof})
                self.assertIn('instance', next(iter(observer.owners.values())), 'source retired before custody')

    def test_only_durably_authorized_producer_can_supply_public_proof(self):
        with Boundary(self.root/'sources', stub_ida=False) as boundary:
            observer = self.observer('authorized-helper')
            value = self.subscribe(observer, boundary)
            rogue = self.observer('unauthorized-source')
            rogue_value = self.subscribe(rogue, boundary, 'unrelated-watch')
            boundary.release_owner()
            until(lambda: observer.items['watch'].get('proof'))
            until(lambda: rogue.items['unrelated-watch'].get('proof'))
            proof = observer.items['watch']['proof']
            # A second real public source has no authorization for the first watch.
            with rogue.lock:
                wrong_source = rogue.publish(value, 'PublicOwnerLifetime',
                    evidence_type='public_owner_lifetime', source='bridge_original')
            with Target(boundary.path) as target:
                with target.locked():
                    journal = Journal(target)
                    with self.assertRaisesRegex(RuntimeError, 'owner/acquisition mismatch'):
                        journal.proof({'watch':'watch', 'proof':wrong_source})
                    for field, changed in (('watch','wrong'), ('subscription_epoch',99),
                                           ('owner',dict(value['owner'], record_id='other-owner')),
                                           ('acquisition',dict(value['acquisition'], ordinal=2))):
                        bad = json.loads(json.dumps(proof))
                        bad['record'][field] = changed
                        with self.assertRaises(RuntimeError):
                            journal.proof({'watch':'watch', 'proof':bad})
                    bad = dict(proof, sha256='0'*64)
                    with self.assertRaisesRegex(RuntimeError, 'content/identity mismatch'):
                        journal.proof({'watch':'watch', 'proof':bad})
                    journal.proof({'watch':'watch', 'proof':proof})
                    self.assertFalse(journal.value['entries']['1']['producer_closed'])
            self.assertEqual(rogue_value['watch'], 'unrelated-watch')

    def test_startup_recovery_rejects_unbound_source_and_changed_launch(self):
        with Boundary(self.root/'startup-binding', stub_ida=False) as boundary:
            observer = self.observer('startup-authorized')
            rogue = self.observer('startup-rogue')
            acquisition = {'parent':'startup', 'purpose':'final', 'ordinal':1}
            launch = {'suffix':boundary.instance.record_id.rsplit('-',1)[1],
                      'source':str(boundary.path), 'target':str(boundary.path), 'backend':'idalib'}
            observer.receive(dict(kind='reserve_parent', protocol=2, helper=observer.incarnation, parent='startup'))
            with Target(boundary.path) as target:
                with target.locked():
                    journal = Journal(target)
                    epoch = journal.begin(acquisition, 'startup', launch=launch)
                    value = dict(watch='startup', subscription_epoch=epoch, target=str(boundary.path),
                                 coord_key=target.key, acquisition=acquisition, launch=launch)
                    receipt = observer.receive(dict(value, kind='launch_intent', protocol=2,
                                                    helper=observer.incarnation))['receipt']
                    journal.launch_signed(receipt)
            observer.discover_startups()
            item = observer.items['startup']
            receipt = item['owner_receipt']
            wrong_source = rogue.publish(dict(item), 'StartupOwnerSubscribed')
            with Target(boundary.path) as target:
                with target.locked():
                    journal = Journal(target)
                    with self.assertRaisesRegex(RuntimeError, 'discovered owner binding mismatch'):
                        journal.startup_owner({'watch':'startup', 'receipt':wrong_source})
                    for field, changed in (('launch',dict(launch, suffix='other')),
                                           ('state_root',dict(item['owner']['state_root'], inode=0)),
                                           ('acquisition',dict(acquisition, ordinal=2))):
                        bad = json.loads(json.dumps(receipt))
                        bad['record'][field] = changed
                        with self.assertRaises(RuntimeError):
                            journal.startup_owner({'watch':'startup', 'receipt':bad})
                    bad = dict(receipt, sha256='0'*64)
                    with self.assertRaisesRegex(RuntimeError, 'content/identity mismatch'):
                        journal.startup_owner({'watch':'startup', 'receipt':bad})
                    journal.recover_public_proofs()
                    self.assertEqual(journal.value['entries'][str(epoch)]['owner'], item['owner'])
                    self.assertFalse(journal.value['entries'][str(epoch)]['producer_closed'])
                    # Discovery can win the race with final lease custody.
                    # Transfer must use the immutable launch, not its cleared
                    # pending-launch field, and retain the exact successor.
                    successor_epoch = journal.begin(acquisition, 'final', owner=item['owner'])
                    successor_value = dict(value, watch='final', subscription_epoch=successor_epoch,
                                           owner=item['owner'])
                    successor_value.pop('launch')
                    successor_receipt = observer.receive(dict(successor_value, kind='subscribe',
                        protocol=2, helper=observer.incarnation))['receipt']
                    journal.owner_signed(successor_receipt)
                    journal.adopt(dict(watch='final', receipt=successor_receipt,
                        owner=item['owner'], acquisition=acquisition, lease={'lease_id':'exact-final'}))
                    transferred = observer.receive(dict(kind='startup_transfer', protocol=2,
                        helper=observer.incarnation, watch='startup', successor='final'))['consumer']
                    journal.startup_transfer(dict(watch='startup', successor='final', consumer=transferred))
                    old = journal.value['entries'][str(epoch)]
                    self.assertEqual(old['launch_identity'], launch)
                    self.assertEqual(old['transferred_to'], successor_epoch)
                    self.assertTrue(old['producer_closed'] and old['consumer_closed'])

    def test_late_public_proof_tombstones_absent_bridge_watch_without_reviving_it(self):
        with Boundary(self.root/'absent-producer', stub_ida=False) as boundary:
            observer = self.observer('startup-proof-helper')
            value = self.subscribe(observer, boundary)
            bridge = SimpleNamespace(lock=threading.RLock(), acquisitions={}, custodians={},
                                     control=SimpleNamespace(send=lambda _:None))
            backup = BackupSources(bridge, 8)
            boundary.release_owner()
            proof = until(lambda: observer.items['watch'].get('proof'))
            receipt = dict(owner=value['owner'], watch=value['watch'],
                           target=value['target'], proof=proof)
            self.assertIsNone(backup.close(receipt))
            self.assertIsNone(backup.close(receipt), 'ACK replay uses the same absence tombstone')
            self.assertEqual(backup.items, {}, 'absence never allocates a producer')
            for register in (lambda: backup.subscribe(boundary.instance, value['owner'], 'watch'),
                             lambda: backup.register(value['owner'], 'watch'),
                             lambda: backup.bind(value)):
                with self.assertRaisesRegex(ValueError, 'ObservationClosed'):
                    register()
            backup.retire('watch')
            with self.assertRaisesRegex(ValueError, 'ObservationClosed'):
                backup.subscribe(boundary.instance, value['owner'], 'watch')
            wrong = dict(receipt, owner=dict(value['owner'], record_id='foreign'))
            with self.assertRaisesRegex(ValueError, 'ProtocolMismatch'):
                backup.close(wrong)

    def test_absent_watch_query_cannot_publish_after_sibling_registration(self):
        from target_coordination import digest
        with Boundary(self.root/'absent-query', stub_ida=False) as boundary:
            observer = self.observer('absent-query-helper')
            old = self.subscribe(observer, boundary)
            other = self.subscribe(observer, boundary, 'other')
            bridge = SimpleNamespace(lock=threading.RLock(), acquisitions={}, custodians={},
                                     control=SimpleNamespace(send=lambda _:None))
            backup = BackupSources(bridge, 8)
            backup.subscribe(boundary.instance, other['owner'], other['watch'])
            with Target(boundary.path) as target, target.locked():
                Journal(target).bridge_signed(backup.bind(other))
            boundary.release_owner()
            proof = until(lambda: observer.items['watch'].get('proof'))
            self.assertIsNone(backup.close(dict(owner=old['owner'], watch=old['watch'],
                target=old['target'], proof=proof)))
            until(lambda: backup.items[digest(old['owner'])]['released'])
            self.assertIsNone(backup.query(old), 'late query must not recreate an absent producer')
            self.assertEqual(backup.query(other)['record']['watch'], 'other')
            self.assertEqual(set(backup.items[digest(old['owner'])]['proofs']), {'other'})
            backup.retire('other')

    def test_two_authorized_public_sources_keep_first_durable_proof_and_both_facts(self):
        with Boundary(self.root/'two-public-sources', stub_ida=False) as boundary:
            observer = self.observer('two-source-helper')
            value = self.subscribe(observer, boundary)
            bridge = SimpleNamespace(lock=threading.RLock(), acquisitions={},
                                     control=SimpleNamespace(send=lambda _:None))
            backup = BackupSources(bridge, 8)
            backup.subscribe(boundary.instance, value['owner'], value['watch'])
            binding = backup.bind(value)
            with Target(boundary.path) as target:
                with target.locked():
                    Journal(target).bridge_signed(binding)
            boundary.release_owner()
            until(lambda: observer.items['watch'].get('proof'))
            helper_proof = observer.items['watch']['proof']
            bridge_proof = until(lambda: backup.query(value))
            with Target(boundary.path) as target:
                with target.locked():
                    journal = Journal(target)
                    first = journal.proof(dict(watch='watch', proof=bridge_proof))['proof']
                    second = journal.proof(dict(watch='watch', proof=helper_proof))['proof']
                    self.assertEqual(first, bridge_proof)
                    self.assertEqual(second, first)
                    self.assertTrue(all(any(f['sha256'] == proof['sha256'] for f in
                        journal.value['entries']['1']['facts']) for proof in (bridge_proof, helper_proof)))
            selected = observer.receive(dict(kind='adopt_public_proof', protocol=2,
                helper=observer.incarnation, watch='watch', proof=first))['proof']
            self.assertEqual(selected, first)
            self.assertEqual(observer.items['watch']['proof'], helper_proof)
            closed = observer.receive(dict(kind='proof_custody_ack', protocol=2,
                helper=observer.incarnation, watch='watch', path=first['path'], sha256=first['sha256']))['consumer']
            self.assertEqual(closed['record']['proof'], first)
            self.assertIn(helper_proof, closed['record']['previous_facts'])
            backup.retire('watch')

    def test_refused_admissions_have_no_unwatched_backup_and_healthy_target_still_fits(self):
        observer = self.observer('admission-helper')
        messages = []
        bridge = SimpleNamespace(lock=threading.Lock(), acquisitions={}, handles={}, custodians={},
            custody_requests={}, stopped=threading.Event(), helper_ready=threading.Event(),
            helper_configuration={'endpoint':'local-ipc-boundary', 'incarnation':observer.incarnation,
                                  'state_root':state_identity()}, control=SimpleNamespace(send=messages.append))
        bridge.helper_ready.set()
        bridge.initialized = threading.Event()
        bridge.initialized.set()
        bridge.backup_sources = BackupSources(bridge, 2)
        class LocalCustodian(Custodian):
            def helper_request(self, value):
                if value['kind'] == 'subscribe' and fault in ('helper-reject', 'helper-ack-loss') and not injected[0]:
                    injected[0] = True
                    if fault == 'helper-ack-loss':
                        observer.receive(dict(value, protocol=2, helper=observer.incarnation))
                    raise RuntimeError('private subscribe boundary fault')
                return observer.receive(dict(value, protocol=2, helper=observer.incarnation))
            def transact(self, action, **fields):
                messages.append(dict(action=action, **fields))
                return {}
        counts = []
        for number,fault in enumerate(('full','enospc','thread-start','helper-reject','helper-ack-loss','healthy')):
            injected = [False]
            with self.subTest(fault=fault), Boundary(self.root/fault, stub_ida=False) as boundary:
                if fault == 'full':
                    with Target(boundary.path) as target:
                        with target.locked():
                            for n in range(LIMIT-RESERVE):
                                Journal(target).begin({'parent':str(n)}, 'pending-'+str(n))
                custody = LocalCustodian(bridge, {}, {'identity':{'operation_id':str(number)}},
                                         time.monotonic()+10, lambda *_:None)
                bridge.acquisitions[str(number)] = custody
                actual_write = Directory.durable
                def write(directory, name, value, **kwargs):
                    if fault == 'enospc' and name == 'custody.json':
                        raise OSError(errno.ENOSPC, 'private journal admission full')
                    return actual_write(directory, name, value, **kwargs)
                try:
                    with custody.gate(boundary.path), patch.object(Directory, 'durable', write):
                        if fault == 'thread-start':
                            with patch('bridge_observer.threading.Thread.start', side_effect=RuntimeError('private Thread.start')):
                                custody.stage('Resolved', boundary.instance)
                        else:
                            custody.stage('Resolved', boundary.instance)
                        self.assertIn(fault, ('helper-ack-loss','healthy'))
                        custody.reconcile_outcome({'attempts':[]})
                        for watch in list(custody.observations):
                            item = observer.items[watch]
                            observer.receive(dict(kind='retire', watch=watch, sha256=item['consumer']['sha256'],
                                                  protocol=2, helper=observer.incarnation))
                            bridge.backup_sources.retire(watch)
                        Journal(custody.target).settle() if custody.target.target_fd is not None else None
                except (RuntimeError, OSError) as exc:
                    self.assertNotIn(fault, ('helper-ack-loss','healthy'), str(exc))
                    custody.fail(exc)
                else:
                    self.assertIn(fault, ('helper-ack-loss','healthy'))
                    custody.fail(RuntimeError('exact no-attach test completion'))
                custody.running = False
                if fault in ('helper-ack-loss','healthy'):
                    Bridge.receive(bridge, None, {'custody_retired':{'lease':None, 'watch':custody.watch,
                        'acquisition':custody.acquisition}})
                boundary.release_owner()
                self.assertEqual(boundary.leases, set(), 'rejected pre-attach paths sent attach')
                self.assertEqual(bridge.backup_sources.items, {}, 'unwatched/provisional source leaked')
                self.assertEqual(observer.items, {})
                self.assertEqual(observer.parents, {})
                self.assertEqual(bridge.acquisitions, {})
                counts.append({'fault':fault, 'backup':0, 'helper':0, 'parent':0})
        (self.root/'admission-result.json').write_text(json.dumps(counts))

    def test_gc_quarantine_and_retirement_reject_cross_home_business_but_keep_evidence_access(self):
        import subprocess
        from cache_store import Store
        cache = self.root/'cache'
        group = cache/'generations/g-fixed'
        group.mkdir(parents=True)
        (group/'generation.json').write_text(json.dumps({'version':1,'key':'private'}))
        (group/'input').write_bytes(b'private input')
        (group/'input.i64').write_bytes(b'private database')
        with Target(group/'input.i64') as target:
            with target.locked():
                lock = (target.directory.path/'lock').stat()
        clock = [1000]
        store = Store(cache, probe=lambda _:None, epoch='private', grace=1, clock=lambda:clock[0])
        isolated = cache/'quarantine/g-fixed/input.i64'
        result = store.collect(0)
        self.assertEqual(result['rejected'], [])
        self.assertTrue(isolated.is_file())
        script = """
import sys,time
from open_recovery import OpenGate
from pathlib import Path
try:
 with OpenGate(Path(sys.argv[2])/'idb', Path(sys.argv[1]), time.monotonic()+2):
  raise AssertionError('quarantined/retired business admitted')
except RuntimeError as exc:
 print(str(exc))
 assert sys.argv[3] in str(exc)
"""
        for status in ('TargetQuarantined','TargetRetired'):
            for path in (group/'input.i64', isolated):
                home = self.root/('other-'+status)
                env = dict(os.environ, HOME=str(home), PYTHONPATH=os.pathsep.join(
                    [str(REPO/'nexus_bridge'),str(REPO/'nexus_bridge/custody')]))
                probe = subprocess.run([sys.executable,'-B','-c',script,str(path),str(home),status],
                                       env=env,capture_output=True,timeout=3)
                self.assertEqual(probe.returncode,0,probe.stderr)
                with Target(path) as target:
                    with target.locked():
                        info = (target.directory.path/'lock').stat()
                        self.assertEqual((info.st_dev,info.st_ino),(lock.st_dev,lock.st_ino))
                        Journal(target).gate()  # Evidence access remains valid.
            clock[0] += 2
            result = store.collect(0)
            self.assertEqual(result['rejected'], [])
        self.assertFalse(isolated.exists())

    def test_legacy_verification_cannot_probe_bad_journal_and_releases_ex_before_rpc(self):
        from open_recovery import open_checked
        path = self.root/'verification.i64'
        path.write_bytes(b'private input')
        with Target(path) as target:
            with target.locked():
                target.directory.durable('custody.json', {'schema':'invalid'})
        calls = []
        Handle = SimpleNamespace(open=lambda *_a,**_kw:calls.append('open'))
        with patch('ida_nexus.probe_database_state', side_effect=lambda *_a,**_kw:calls.append('probe')):
            with self.assertRaisesRegex(RuntimeError,'corrupt custody journal'):
                open_checked(Handle,lambda **kw:kw,str(path),{},time.monotonic()+2,lambda *_:'pass',{})
        self.assertEqual(calls,[])
        healthy = self.root/'healthy.i64'
        healthy.write_bytes(b'private input')
        def execute(*_args,**_kwargs):
            with Target(healthy) as target:
                with target.locked(nb=True):
                    pass
            return {'result':'9.5'}
        handle = SimpleNamespace(instance=SimpleNamespace(record_id='private-owner'),execute_python=execute)
        with patch('ida_nexus.probe_database_state', return_value={'state':'packed'}):
            result = open_checked(SimpleNamespace(open=lambda *_a,**_kw:handle),lambda **kw:kw,
                str(healthy),{},time.monotonic()+2,lambda *_:'pass',{})
        self.assertIs(result[0],handle)


if __name__ == '__main__':
    unittest.main()
