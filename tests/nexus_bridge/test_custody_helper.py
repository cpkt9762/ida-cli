"""Real independent helper and public SDK lifetime, using private owner inputs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import stat
import time
import unittest
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'nexus_bridge/custody'), str(REPO / 'tests/support')]
from owner_identity import owner_key, state_identity
from proof_helper import Observer, request
from r0_transport import Boundary
from target_coordination import Target
from target_journal import Journal
from helper_readiness import bind_window_case


class HelperCustody(unittest.TestCase):
    def setUp(self):
        Path(os.environ['R3A_CASE_ROOT']).mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='h-', dir=os.environ['R3A_CASE_ROOT']))
        self.children = []
        self.identity = uuid.uuid4().hex

    def tearDown(self):
        rows = []
        for child in self.children:
            try:
                code = child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.terminate()
                code = child.wait(timeout=3)
                rows.append({'pid':child.pid, 'forced':True, 'exit':code})
            else:
                rows.append({'pid':child.pid, 'forced':False, 'exit':code})
            bound = getattr(child, '_fixture_endpoint', None)
            if bound is not None:
                endpoint, inode = bound
                try:
                    current = endpoint.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == inode:
                    endpoint.unlink()  # Actual wait above ended this exact creator.
        (self.root / 'audit.json').write_text(json.dumps(rows))
        self.assertFalse(any(row['forced'] for row in rows), 'helper must naturally finish after custody')

    def start_helper(self, *, directory=None, state=None):
        directory = directory or self.root
        directory.mkdir(mode=0o700, exist_ok=True)
        endpoint = directory / 'h'
        previous_inode = None
        try:
            previous = endpoint.lstat()
        except FileNotFoundError:
            pass
        else:
            previous_inode = (previous.st_dev, previous.st_ino)
            owned_exit = any(getattr(child, '_fixture_endpoint', None) == (endpoint, previous_inode)
                             and child.poll() is not None for child in self.children)
            if (not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != os.getuid()
                    or stat.S_IMODE(previous.st_mode) != 0o600 or not owned_exit):
                raise RuntimeError('untrusted helper startup preexisting endpoint')
        log = (directory / 'helper.log').open('ab')
        environment = dict(os.environ, PYTHONPATH='')
        if state is not None:
            state.mkdir(mode=0o700, parents=True, exist_ok=True)
            environment['IDA_NEXUS_STATE_DIR'] = str(state)
        child = subprocess.Popen([sys.executable, '-B', str(REPO / 'nexus_bridge/custody/proof_helper.py'),
                                  str(endpoint), self.identity, '8'],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                 start_new_session=True, env=environment)
        log.close()
        self.children.append(child)
        deadline = time.monotonic() + 2
        published_inode = None
        while True:
            if child.poll() is not None or time.monotonic() >= deadline:
                self.fail('helper startup failed: ' + (directory / 'helper.log').read_text())
            try:
                info = endpoint.lstat()
            except FileNotFoundError:
                if published_inode is not None:
                    raise RuntimeError('helper startup endpoint disappeared')
                time.sleep(.002)
                continue
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise RuntimeError('untrusted helper startup endpoint type or uid')
            inode = (info.st_dev, info.st_ino)
            if inode == previous_inode:
                time.sleep(.002)  # Only the exact exited fixture child may be rebound.
                continue
            if published_inode is not None and inode != published_inode:
                raise RuntimeError('helper startup endpoint replaced')
            published_inode = inode
            if stat.S_IMODE(info.st_mode) != 0o600:
                # bind precedes chmod/listen. Only this owned child's pinned
                # socket may still be publishing; request remains fully strict.
                time.sleep(.002)
                continue
            try:
                status = request(endpoint, self.identity, {'kind':'heartbeat'},
                                 timeout=max(.001, deadline-time.monotonic()))
            except ConnectionRefusedError:
                time.sleep(.002)  # chmod may precede listen on the same inode.
                continue
            after = endpoint.lstat()
            if ((after.st_dev, after.st_ino) != published_inode
                    or not stat.S_ISSOCK(after.st_mode) or after.st_uid != os.getuid()
                    or stat.S_IMODE(after.st_mode) != 0o600):
                raise RuntimeError('helper startup endpoint changed after heartbeat')
            break
        if state is None:
            self.assertEqual(status['state_root'], state_identity())
        else:
            self.assertEqual(status['state_root']['path'],str(state.resolve()))
        self.assertEqual(status['identity']['sid'], child.pid, 'helper must have its own session')
        self.assertEqual(status['identity']['pid'], child.pid, 'ready peer must be this owned helper')
        child._fixture_endpoint = (endpoint, published_inode)
        return endpoint

    def test_bind_publication_window_waits_for_trusted_same_helper(self):
        """Actual start_helper/request/main; pipe and lstat scheduling only."""
        self.bind_window_case()

    def test_bind_publication_replaced_inode_is_not_a_readiness_retry(self):
        self.bind_window_case('replace')

    def test_bind_publication_wrong_uid_metadata_is_not_a_readiness_retry(self):
        # UID input is controlled; no privileged chown or peer impersonation.
        self.bind_window_case('uid')

    def test_bind_publication_regular_file_is_not_a_readiness_retry(self):
        self.bind_window_case('file')

    def bind_window_case(self, fault=None):
        bind_window_case(self, fault)

    def test_readiness_peer_and_incarnation_errors_are_not_retried(self):
        from unittest.mock import patch
        real_request = request
        for fault in ('id', 'pe'):
            with self.subTest(fault=fault):
                directory = self.root/fault
                endpoint = directory/'h'
                rejected = []
                def invalid_peer(path, incarnation, value, **options):
                    try:
                        if fault == 'id':
                            return real_request(path, 'wrong-helper', value, **options)
                        with patch('proof_helper.peer_uid', return_value=os.getuid()+1):
                            return real_request(path, incarnation, value, **options)
                    except RuntimeError as error:
                        rejected.append(str(error))
                        raise
                try:
                    expected = 'response identity' if fault == 'id' else 'replaced or wrong peer'
                    with patch.dict(globals(), request=invalid_peer):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            self.start_helper(directory=directory)
                    self.assertEqual(len(rejected), 1, 'protocol errors must escape the first real RPC')
                finally:
                    real_request(endpoint, self.identity, {'kind':'finish'})
                    self.assertEqual(self.children[-1].wait(timeout=3), 0)

    def test_preexisting_live_or_unowned_socket_is_never_adopted(self):
        import socket
        endpoint = self.start_helper(directory=self.root/'lv')
        try:
            before = endpoint.lstat()
            with self.assertRaisesRegex(RuntimeError, 'preexisting endpoint'):
                self.start_helper(directory=self.root/'lv')
            self.assertEqual(len(self.children), 1, 'no second child for a live endpoint')
            self.assertEqual(endpoint.lstat().st_ino, before.st_ino)
        finally:
            request(endpoint, self.identity, {'kind':'finish'})
            self.assertEqual(self.children[-1].wait(timeout=3), 0)
        directory = self.root/'fo'
        directory.mkdir(mode=0o700)
        endpoint = directory/'h'
        with socket.socket(socket.AF_UNIX) as foreign:
            foreign.bind(str(endpoint))
            endpoint.chmod(0o600)
            inode = endpoint.lstat().st_ino
            with self.assertRaisesRegex(RuntimeError, 'preexisting endpoint'):
                self.start_helper(directory=directory)
            self.assertEqual(len(self.children), 1, 'unknown endpoints cannot gain fixture custody')
            self.assertEqual(endpoint.lstat().st_ino, inode)
        endpoint.unlink()  # The substitute was created in this test above.

    def test_compaction_io_failure_allows_existing_public_proof_and_closures(self):
        """Actual SDK/helper/writer; only the old routine closure is a fixture."""
        from unittest.mock import patch
        from target_coordination import digest
        import errno
        with Boundary(self.root/'owner') as boundary:
            endpoint=self.start_helper()
            owner=owner_key(boundary.instance)
            acquisition={'parent':'routine-emergency','purpose':'final','ordinal':1}
            request(endpoint,self.identity,{'kind':'reserve_parent','parent':'routine-emergency'})
            with Target(boundary.path) as target,target.locked():
                journal=Journal(target)
                epoch=journal.begin(acquisition,'live-cleanup',owner=owner)
                value=dict(watch='live-cleanup',target=str(boundary.path),subscription_epoch=epoch,
                    coord_key=target.key,owner=owner,acquisition=acquisition)
            signed=request(endpoint,self.identity,dict(value,kind='subscribe'))['receipt']
            with Target(boundary.path) as target,target.locked():
                journal=Journal(target)
                journal.owner_signed(signed)
                old=journal.begin({'parent':'closed-fixture','purpose':'final','ordinal':1},'closed-fixture')
                observations=target.directory.child('observations')
                directory=observations.child('closed-fixture')
                try:
                    directory.durable('routine-denied.json',{'kind':'NoAttach','fixture':'no SDK/public proof claim'})
                    _,info,raw=directory.read('routine-denied.json')
                    reference={'path':str(directory.path/'routine-denied.json'),'sha256':digest(raw),
                        'inode':[info.st_dev,info.st_ino],'kind':'NoAttach'}
                finally:directory.close();observations.close()
                journal.value['entries'][str(old)].update(facts=[reference],producer_closed=True,
                    consumer_closed=True,detached=True,bridge_closed=True,unacked_events=False)
                journal.save()
                original=os.unlink
                def deny(name,*args,**kwargs):
                    if name=='routine-denied.json':raise OSError(errno.EACCES,'controlled routine refusal')
                    return original(name,*args,**kwargs)
                with patch('target_journal.os.unlink',deny):
                    with self.assertRaisesRegex(OSError,'RoutineCompactionFailed'):journal.settle()
            boundary.release_owner()
            deadline=time.monotonic()+2
            while True:
                item=request(endpoint,self.identity,{'kind':'lookup','watch':'live-cleanup'})['item']
                if item.get('proof'):break
                self.assertLess(time.monotonic(),deadline,'actual public lifetime proof deadline')
                time.sleep(.002)
            proof=item['proof']
            rows=[]
            def writer(action,**fields):
                message=dict(target=value['target'],coord_key=value['coord_key'],watch=value['watch'],action=action,**fields)
                argv=['timeout','10s',sys.executable,'-B',str(REPO/'tests/support/r4_journal_io.py'),str(REPO)]
                before=subprocess.check_output(['uptime'],text=True).strip()
                result=subprocess.run(argv,input=json.dumps(message),capture_output=True,text=True,check=False)
                rows.append(dict(argv=argv,action=action,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                    uptime_before=before,uptime_after=subprocess.check_output(['uptime'],text=True).strip()))
                (self.root/'emergency-writer.json').write_text(json.dumps(rows,indent=2))
                return result
            denied=writer('accounting')
            self.assertNotEqual(denied.returncode,0)
            self.assertIn('RoutineCompactionFailed',denied.stderr)
            accepted=writer('proof',proof=proof)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            consumer=request(endpoint,self.identity,{'kind':'proof_custody_ack','watch':value['watch'],
                'path':proof['path'],'sha256':proof['sha256']})['consumer']
            accepted=writer('producer_closed',consumer=consumer)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            publisher=Observer('bridge-emergency-'+self.identity,8)
            closed=publisher.publish(value,'BridgeProducerClosed',proof=proof,previous_facts=[])
            accepted=writer('bridge_closed',consumer=closed)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            self.assertTrue(Path(reference['path']).exists(),'routine failure must keep its original evidence')
            with Target(boundary.path) as target,target.locked():
                journal=Journal(target,compact=False)
                live=journal.value['entries'][str(epoch)]
                self.assertTrue(live['proof'] and live['producer_closed'] and live['consumer_closed'] and live['bridge_closed'])
                self.assertIsNotNone(journal.value['compaction'])
                resumed=Journal(target)
                resumed.settle()
                self.assertEqual(resumed.value['entries'],{})
            request(endpoint,self.identity,{'kind':'retire','watch':'live-cleanup','sha256':consumer['sha256']})
            request(endpoint,self.identity,{'kind':'retire_parent','parent':'routine-emergency'})
            request(endpoint,self.identity,{'kind':'finish'})

    def recovery_case(self, released_before_crash):
        with Boundary(self.root / 'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            watch = uuid.uuid4().hex
            acquisition = {'parent':'recovery-parent', 'purpose':'final', 'ordinal':1}
            with Target(boundary.path) as target:
                with target.locked():
                    epoch = Journal(target).begin(acquisition, watch, owner=owner_key(boundary.instance))
            request(endpoint, self.identity, {'kind':'reserve_parent', 'parent':'recovery-parent'})
            value = {'kind':'subscribe', 'watch':watch, 'target':str(boundary.path), 'subscription_epoch':1,
                     'coord_key':coord, 'owner':owner_key(boundary.instance),
                     'acquisition':{'parent':'recovery-parent', 'purpose':'final', 'ordinal':1}}
            receipt = request(endpoint, self.identity, value)['receipt']
            self.assertEqual(epoch, value['subscription_epoch'])
            with Target(boundary.path) as target:
                with target.locked():
                    Journal(target).owner_signed(receipt)
            def proof():
                deadline = time.monotonic()+2
                while True:
                    item = request(endpoint, self.identity, {'kind':'lookup', 'watch':watch})['item']
                    if item.get('proof'):
                        return item['proof']
                    if time.monotonic() >= deadline:
                        self.fail('public proof pending after real owner unlock: ' + str(item))
                    time.sleep(.002)
            before = None
            if released_before_crash:
                boundary.release_owner()
                before = proof()
            old = self.children[-1]
            old.kill()  # Explicit fault injection into our exact Popen child.
            self.assertEqual(old.wait(timeout=2), -9)
            (self.root/'fault.json').write_text(json.dumps({'kind':'injected_helper_crash','pid':old.pid}))
            endpoint = self.start_helper()
            status = request(endpoint, self.identity, {'kind':'heartbeat'})
            self.assertTrue(status['recovered'])
            self.assertEqual(status['used'], 1, 'restart must not reset active capacity')
            self.assertEqual(status['items'][0]['receipt'], receipt)
            if not released_before_crash:
                self.assertNotIn('proof', status['items'][0], 'helper death is not owner lifetime proof')
                boundary.release_owner()
            after = proof()
            if before:
                self.assertEqual(after, before, 'reuse the durable proof after original source disappeared')
            # A new process takes target authority and recovers only the exact
            # helper proof. It cannot close either original producer or settle.
            script = '''
import json,sys
from target_coordination import Target
from target_journal import Journal
with Target(sys.argv[1]) as target:
 with target.locked():
  journal=Journal(target)
  journal.gate()
  print(json.dumps(journal.value))
'''
            writer = subprocess.run([sys.executable, '-B', '-c', script, str(boundary.path)],
                env=dict(os.environ, PYTHONPATH=str(REPO/'nexus_bridge/custody')),
                capture_output=True, timeout=3)
            self.assertEqual(writer.returncode, 0, writer.stderr)
            recovered = json.loads(writer.stdout)['entries'][str(epoch)]
            self.assertEqual(recovered['proof']['sha256'], after['sha256'])
            self.assertTrue(recovered['consumer_closed'])
            self.assertFalse(recovered['producer_closed'])
            self.assertTrue(Path(receipt['path']).is_file(), 'last producer reference survives recovery')
            request(endpoint, self.identity, {'kind':'proof_custody_ack', 'watch':watch,
                'path':after['path'], 'sha256':after['sha256']})
            consumer = request(endpoint, self.identity, {'kind':'lookup', 'watch':watch})['item']['consumer']
            request(endpoint, self.identity, {'kind':'retire', 'watch':watch, 'sha256':consumer['sha256']})
            request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'recovery-parent'})
            request(endpoint, self.identity, {'kind':'finish'})

    def test_helper_crash_reconnects_exact_live_public_source_without_resetting_capacity(self):
        self.recovery_case(False)

    def test_helper_crash_reuses_durable_public_proof_after_source_disappears(self):
        self.recovery_case(True)

    def test_reference_hole_and_interrupted_compaction_keep_exact_public_facts(self):
        from unittest.mock import patch
        with Boundary(self.root/'owner') as boundary:
            endpoint = self.start_helper()
            owner = owner_key(boundary.instance)
            acquisition = {'parent':'holes', 'purpose':'final', 'ordinal':1}
            request(endpoint, self.identity, {'kind':'reserve_parent', 'parent':'holes'})
            values = []
            for watch in ('first', 'second'):
                with Target(boundary.path) as target:
                    with target.locked():
                        epoch = Journal(target).begin(acquisition, watch, owner=owner)
                        coord = target.key
                value = dict(watch=watch, target=str(boundary.path), subscription_epoch=epoch,
                             coord_key=coord, owner=owner, acquisition=acquisition)
                signed = request(endpoint, self.identity, dict(value, kind='subscribe'))['receipt']
                with Target(boundary.path) as target:
                    with target.locked():
                        Journal(target).owner_signed(signed)
                values.append(value)
            boundary.release_owner()  # Only the real public wait produces proof.
            proofs = []
            for value in values:
                deadline = time.monotonic()+2
                while True:
                    item = request(endpoint, self.identity, {'kind':'lookup', 'watch':value['watch']})['item']
                    if item.get('proof'):
                        proofs.append(item['proof'])
                        break
                    self.assertLess(time.monotonic(), deadline, 'exact public proof deadline')
                    time.sleep(.002)
            publisher = Observer('bridge-test-'+self.identity, 8)
            for value, proof in reversed(list(zip(values, proofs))):
                with Target(boundary.path) as target:
                    with target.locked():
                        journal = Journal(target)
                        wrong = json.loads(json.dumps(proof))
                        wrong['record']['owner']['record_id'] += '-different-owner'
                        with self.assertRaisesRegex(RuntimeError, 'owner/acquisition mismatch'):
                            journal.proof({'watch':value['watch'], 'proof':wrong})
                        journal.proof({'watch':value['watch'], 'proof':proof})
                        journal.settle()
                        self.assertTrue(Path(proof['path']).is_file(), 'unclosed producer retains proof')
                consumer = request(endpoint, self.identity, {'kind':'proof_custody_ack',
                    'watch':value['watch'], 'path':proof['path'], 'sha256':proof['sha256']})['consumer']
                closed = publisher.publish(value, 'BridgeProducerClosed', proof=proof, previous_facts=[])
                with Target(boundary.path) as target:
                    with target.locked():
                        journal = Journal(target)
                        journal.producer_closed({'watch':value['watch'], 'consumer':consumer})
                        journal.bridge_closed({'watch':value['watch'], 'consumer':closed})
                        if value['watch'] == 'second':
                            with patch('target_journal.os.unlink', side_effect=OSError('injected compaction interruption')):
                                with self.assertRaisesRegex(OSError, 'compaction interruption'):
                                    journal.settle()
                            self.assertTrue(Path(proof['path']).is_file(), 'failed unlink retains last evidence')
                            durable, _, _ = target.directory.read('custody.json')
                            self.assertIsNotNone(durable['compaction'], 'durable exact deletion intent precedes unlink')
                            journal = Journal(target)  # Resume from the actual durable intent.
                            self.assertEqual(journal.value['closed_through'], 0)
                            self.assertEqual(journal.value['closed_after_holes'], [[2, 2]])
                            self.assertTrue(Path(proofs[0]['path']).is_file(), 'older reference hole must survive')
                        else:
                            journal.settle()
                            self.assertEqual(journal.value['closed_through'], 2)
                            self.assertEqual(journal.value['closed_after_holes'], [])
                            self.assertEqual(journal.value['entries'], {})
                        with self.assertRaisesRegex(RuntimeError, 'old/unknown epoch'):
                            journal.item(value['watch'], value['subscription_epoch'])
                request(endpoint, self.identity, {'kind':'retire', 'watch':value['watch'],
                                                 'sha256':consumer['sha256']})
            request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'holes'})
            request(endpoint, self.identity, {'kind':'finish'})

    def test_public_proof_is_durable_before_custody_and_instance_retained_until_ack(self):
        with Boundary(self.root / 'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            watch = uuid.uuid4().hex
            request(endpoint, self.identity, {'kind':'reserve_parent', 'parent':'fixture-parent'})
            value = {'kind':'subscribe', 'watch':watch, 'target':str(boundary.path), 'subscription_epoch':1,
                     'coord_key':coord, 'owner':owner_key(boundary.instance),
                     'acquisition':{'parent':'fixture-parent', 'purpose':'final', 'ordinal':1}}
            receipt = request(endpoint, self.identity, value)['receipt']
            self.assertEqual(hashlib.sha256(Path(receipt['path']).read_bytes()).hexdigest(), receipt['sha256'])
            self.assertEqual(request(endpoint, self.identity, value)['receipt'], receipt, 'lost ACK replay is idempotent')
            status = request(endpoint, self.identity, {'kind':'heartbeat'})
            self.assertNotIn('proof', status['items'][0], 'owner still holds real lifetime flock')
            boundary.release_owner()
            deadline = time.monotonic() + 2
            while True:
                status = request(endpoint, self.identity, {'kind':'heartbeat'})
                item = status['items'][0]
                if item.get('proof') or time.monotonic() >= deadline:
                    break
                time.sleep(.002)
            proof = item.get('proof')
            self.assertIsNotNone(proof, status)
            proof_path = Path(proof['path'])
            self.assertEqual(proof_path.parent.parent.name, 'proofs')
            self.assertEqual(hashlib.sha256(proof_path.read_bytes()).hexdigest(), proof['sha256'])
            self.assertEqual(proof['record']['owner'], value['owner'])
            before = proof_path.read_bytes()
            ack = {'kind':'proof_custody_ack', 'watch':watch, 'path':proof['path'], 'sha256':proof['sha256']}
            closed = request(endpoint, self.identity, ack)['consumer']
            self.assertEqual(request(endpoint, self.identity, ack)['consumer'], closed)
            self.assertEqual(proof_path.read_bytes(), before, 'ACK is not a deletion permission')
            request(endpoint, self.identity, {'kind':'retire', 'watch':watch, 'sha256':closed['sha256']})
            request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'fixture-parent'})
            request(endpoint, self.identity, {'kind':'finish'})

    def test_wrong_root_and_wrong_owner_never_get_subscription(self):
        with Boundary(self.root / 'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            owner = owner_key(boundary.instance)
            owner['state_root'] = dict(owner['state_root'], inode=owner['state_root']['inode'] + 1)
            request(endpoint, self.identity, {'kind':'reserve_parent', 'parent':'wrong-parent'})
            with self.assertRaisesRegex(RuntimeError, 'wrong state root'):
                request(endpoint, self.identity, {'kind':'subscribe', 'watch':'wrong',
                    'target':str(boundary.path), 'coord_key':coord, 'owner':owner, 'subscription_epoch':1,
                    'acquisition':{'parent':'wrong-parent', 'purpose':'final', 'ordinal':1}})
            self.assertEqual(request(endpoint, self.identity, {'kind':'heartbeat'})['items'], [])
            original=owner_key(boundary.instance)
            variants=[]
            for field,value in (('record_id',original['record_id']+'-foreign'),
                    ('pid',original['pid']+1),('started_at',original['started_at']+1),
                    ('canonical_idb_path',str((self.root/'other.i64').resolve())),('backend','gui')):
                changed=dict(original,**{field:value})
                absent=dict(original);absent.pop(field)
                variants.extend(((field,'changed',changed),(field,'absent',absent)))
            evidence=[]
            for number,(field,variant,changed) in enumerate(variants):
                with self.subTest(field=field,variant=variant):
                    with self.assertRaisesRegex(RuntimeError,'ProtocolMismatch|exact public instance unavailable') as failure:
                        request(endpoint,self.identity,{'kind':'subscribe','watch':'foreign-'+str(number),
                            'target':str(boundary.path),'coord_key':coord,'owner':changed,'subscription_epoch':1,
                            'acquisition':{'parent':'wrong-parent','purpose':'final','ordinal':1}})
                    self.assertEqual(request(endpoint,self.identity,{'kind':'heartbeat'})['items'],[])
                    evidence.append(dict(field=field,variant=variant,error=str(failure.exception),proof=False))
            (self.root/'owner-field-matrix.json').write_text(json.dumps(evidence,indent=2))
            request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'wrong-parent'})
            request(endpoint, self.identity, {'kind':'finish'})

    def test_startup_only_orphan_abandons_durably_without_fabricating_release(self):
        target_path = self.root / 'tiny.i64'
        target_path.write_bytes(b'private input')
        with Target(target_path) as target:
            with target.locked():
                coord = target.key
        clock = [10.0]
        observer = Observer(self.identity, 8, clock=lambda:clock[0])
        observer.receive({'kind':'reserve_parent', 'protocol':2, 'helper':self.identity, 'parent':'startup-parent'})
        receipt = observer.receive({'kind':'launch_intent', 'protocol':2, 'helper':self.identity,
            'watch':'startup-only', 'target':str(target_path), 'coord_key':coord, 'subscription_epoch':1,
            'launch':{'suffix':'private-suffix', 'target':str(target_path), 'backend':'idalib'},
            'acquisition':{'parent':'startup-parent', 'purpose':'final', 'ordinal':1}})['receipt']
        self.assertTrue(Path(receipt['path']).is_file())
        clock[0] = 309.9
        self.assertFalse(observer.orphan_done())
        clock[0] = 310.0
        self.assertTrue(observer.orphan_done())
        item = observer.items['startup-only']
        self.assertNotIn('proof', item)
        self.assertEqual(item['abandoned']['record']['kind'], 'ObservationAbandoned')
        self.assertTrue(Path(item['abandoned']['path']).is_file())

    def test_parent_budget_is_reserved_before_side_effect_and_returned_only_without_watches(self):
        observer = Observer(self.identity, 8)
        def call(kind, **fields):
            return observer.receive(dict(kind=kind, protocol=2, helper=self.identity, **fields))
        call('reserve_parent', parent='a')
        call('reserve_parent', parent='a')
        call('reserve_parent', parent='b')
        self.assertEqual(call('heartbeat')['reserved'], 8)
        with self.assertRaisesRegex(RuntimeError, 'reservation capacity'):
            call('reserve_parent', parent='c')
        self.assertTrue(call('retire_parent', parent='a')['retired'])
        call('reserve_parent', parent='c')
        self.assertEqual(call('heartbeat')['parent_count'], 2)

    def test_typed_no_attach_closes_watch_without_owner_release_or_public_proof(self):
        with Boundary(self.root / 'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            request(endpoint, self.identity, {'kind':'reserve_parent', 'parent':'no-attach'})
            owner = owner_key(boundary.instance)
            watch = uuid.uuid4().hex
            request(endpoint, self.identity, {'kind':'subscribe', 'watch':watch, 'target':str(boundary.path), 'subscription_epoch':1,
                'coord_key':coord, 'owner':owner,
                'acquisition':{'parent':'no-attach', 'purpose':'final', 'ordinal':1}})
            self.assertFalse(request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'no-attach'})['retired'])
            attempt = {'attempt':1, 'owner':owner, 'state':'may_send'}
            request(endpoint, self.identity, {'kind':'attach_attempt', 'watch':watch, 'attempt':attempt})
            with self.assertRaisesRegex(RuntimeError, 'terminal attempts'):
                request(endpoint, self.identity, {'kind':'no_attach', 'watch':watch})
            request(endpoint, self.identity, {'kind':'attach_attempt', 'watch':watch,
                'attempt':dict(attempt, state='lease_absent')})
            closed = request(endpoint, self.identity, {'kind':'no_attach', 'watch':watch})['consumer']
            item = request(endpoint, self.identity, {'kind':'lookup', 'watch':watch})['item']
            self.assertNotIn('proof', item)
            self.assertFalse(boundary.released, 'no attach never proves owner lifetime')
            self.assertEqual(closed['record']['kind'], 'NoAttachClosed')
            request(endpoint, self.identity, {'kind':'retire', 'watch':watch, 'sha256':closed['sha256']})
            request(endpoint, self.identity, {'kind':'retire_parent', 'parent':'no-attach'})
            request(endpoint, self.identity, {'kind':'finish'})


    def test_orphan_write_failure_retains_responsibility_and_exits_with_recovery_diagnostic(self):
        from unittest.mock import patch
        target_path = self.root/'orphan.i64'
        target_path.write_bytes(b'private input')
        with Target(target_path) as target:
            with target.locked():
                coord = target.key
        clock = [0.0]
        from target_coordination import Directory
        storage = Directory(self.root)
        self.addCleanup(storage.close)
        observer = Observer(self.identity, 8, clock=lambda:clock[0], storage=storage)
        def call(kind, **fields):
            return observer.receive(dict(kind=kind, protocol=2, helper=self.identity, **fields))
        call('reserve_parent', parent='orphan')
        call('launch_intent', watch='startup', target=str(target_path), coord_key=coord, subscription_epoch=1,
             acquisition={'parent':'orphan','purpose':'final','ordinal':1},
             launch={'suffix':'no-public-owner','target':str(target_path),'backend':'idalib'})
        clock[0] = 300
        with patch.object(observer, 'publish', side_effect=OSError('injected durable storage failure')):
            self.assertTrue(observer.orphan_done(), 'failed target publication cannot keep an orphan process forever')
        saved = storage.read('helper-state.json')[0]
        self.assertEqual(saved['orphan_exit']['status'], 'publication_failed')
        self.assertIn('durable storage failure', saved['exit_blocked'])
        self.assertIn('startup', saved['items'])
        self.assertFalse(saved['finishing'], 'orphan exit is not a release/finish tombstone')
        self.assertIn('startup', observer.items)
        self.assertNotIn('proof', observer.items['startup'])
        self.assertNotIn('abandoned', observer.items['startup'])
        self.assertIn('durable storage failure', observer.exit_blocked)
        self.assertTrue(observer.orphan_done())
        self.assertEqual(observer.items['startup']['abandoned']['record']['kind'], 'ObservationAbandoned')

    def test_orphan_parent_exit_removes_exact_socket_on_publish_success_and_failure(self):
        import shutil
        from process_identity import identity, same_process
        import itertools
        for mode, failure in itertools.product(('clock', 'term'), (False, True)):
            with self.subTest(mode=mode, publication_failure=failure):
                case = self.root / (mode + str(failure))
                case.mkdir(mode=0o700)
                parent = subprocess.Popen([sys.executable, '-B', str(REPO / 'tests/support/helper_orphan_parent.py'), str(case)])
                self.children.append(parent)
                deadline = time.monotonic()+5
                while not (case/'ready.json').exists():
                    self.assertIsNone(parent.poll())
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(.002)
                born = json.loads((case/'ready.json').read_text())
                try:
                    (case/'parent-exit').touch()
                    self.assertEqual(parent.wait(timeout=3),0)
                    if failure:
                        shutil.rmtree(case/'target')
                    if mode == 'clock':
                        (case/'clock').write_bytes((301).to_bytes(8,'big'))
                    else:
                        import signal
                        self.assertTrue(same_process(identity(born['pid']),born['identity']))
                        os.kill(born['pid'],signal.SIGTERM)
                    while same_process(identity(born['pid']),born['identity']):
                        self.assertLess(time.monotonic(),deadline,'orphan must exit despite failed publication')
                        time.sleep(.002)
                    self.assertFalse((case/'helper/h').exists())
                    saved = json.loads((case/'helper/helper-state.json').read_text())
                    self.assertEqual(saved['orphan_exit']['cause'], 'termination requested' if mode == 'term' else 'router disconnected')
                    self.assertFalse(saved['finishing'])
                    self.assertIn('pending',saved['items'])
                    self.assertNotIn('proof',saved['items']['pending'])
                    self.assertEqual(saved['orphan_exit']['status'],'publication_failed' if failure else 'published')
                    self.assertEqual('abandoned' in saved['items']['pending'],not failure)
                    if failure:
                        self.assertIn('ObservationRecoveryBlocked', (case/'helper.log').read_text())
                finally:
                    if same_process(identity(born['pid']),born['identity']):
                        import signal
                        os.kill(born['pid'],signal.SIGKILL)  # Exact recorded test birth only; assertion remains failed.

    def test_missing_original_source_after_restart_is_blocked_without_fake_proof(self):
        with Boundary(self.root/'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            request(endpoint, self.identity, {'kind':'reserve_parent','parent':'missing'})
            request(endpoint, self.identity, {'kind':'subscribe','watch':'missing-watch','subscription_epoch':1,
                'target':str(boundary.path),'coord_key':coord,'owner':owner_key(boundary.instance),
                'acquisition':{'parent':'missing','purpose':'final','ordinal':1}})
            child = self.children[-1]
            child.kill()
            self.assertEqual(child.wait(timeout=2), -9)
            boundary.release_owner()
            endpoint = self.start_helper()
            status = request(endpoint,self.identity,{'kind':'heartbeat'})
            self.assertEqual(status['used'],1)
            self.assertNotIn('proof',status['items'][0])
            self.assertIn('ObservationRecoveryBlocked',status['items'][0]['observation_error'])
            # Deliberate exact-child crash fault ends this blocked test. No
            # release/retirement is synthesized to make teardown pass.
            child = self.children[-1]
            child.kill()
            self.assertEqual(child.wait(timeout=2), -9)
            (self.root/'fault.json').write_text(json.dumps({'kind':'injected_missing_source_crashes',
                'pids':[p.pid for p in self.children], 'expected':'responsibility remains blocked'}))



    def test_two_state_roots_have_independent_helpers_and_reject_cross_root_owner(self):
        first = self.start_helper()
        second = self.start_helper(directory=self.root/'second', state=self.root/'state-b')
        a = request(first,self.identity,{'kind':'heartbeat'})
        b = request(second,self.identity,{'kind':'heartbeat'})
        self.assertNotEqual(a['state_root'],b['state_root'])
        self.assertNotEqual(a['identity']['pid'],b['identity']['pid'])
        with Boundary(self.root/'owner') as boundary:
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            request(second,self.identity,{'kind':'reserve_parent','parent':'cross'})
            with self.assertRaisesRegex(RuntimeError,'wrong state root'):
                request(second,self.identity,{'kind':'subscribe','watch':'cross-root','subscription_epoch':1,
                    'target':str(boundary.path),'coord_key':coord,'owner':owner_key(boundary.instance),
                    'acquisition':{'parent':'cross','purpose':'final','ordinal':1}})
            self.assertEqual(request(second,self.identity,{'kind':'heartbeat'})['used'],0)
            request(second,self.identity,{'kind':'retire_parent','parent':'cross'})
        request(first,self.identity,{'kind':'finish'})
        request(second,self.identity,{'kind':'finish'})
        (self.root/'roots.json').write_text(json.dumps({'first':a,'second':b}))

    def test_helper_schema_mismatch_has_no_side_effect_or_reserved_capacity(self):
        observer = Observer(self.identity,8)
        base = {'kind':'reserve_parent','protocol':2,'helper':self.identity,'parent':'malformed'}
        for message in (dict(base, protocol=1), dict(base, protocol=True), dict(base, future=True),
                        dict(base, helper='wrong'), {k:v for k,v in base.items() if k != 'parent'},
                        dict(base,kind='future')):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError,'ProtocolMismatch'):
                observer.receive(message)
            self.assertEqual(observer.items,{})
            self.assertEqual(observer.parents,{})
            self.assertEqual(observer.seq,0)



    def test_startup_birth_ack_replay_and_public_late_owner_transfer(self):
        from custody_process_identity import capture
        with Boundary(self.root/'owner') as boundary:
            endpoint = self.start_helper()
            with Target(boundary.path) as target:
                with target.locked():
                    coord = target.key
            request(endpoint,self.identity,{'kind':'reserve_parent','parent':'startup-late'})
            launch = {'suffix':boundary.instance.record_id.rsplit('-',1)[-1],
                      'source':str(boundary.path),'target':str(boundary.path),'backend':'idalib'}
            intent = {'kind':'launch_intent','watch':'startup-late','subscription_epoch':1,
                      'target':str(boundary.path),'coord_key':coord,'launch':launch,
                      'acquisition':{'parent':'startup-late','purpose':'final','ordinal':1}}
            signed = request(endpoint,self.identity,intent)['receipt']
            self.assertEqual(request(endpoint,self.identity,intent)['receipt'],signed)
            changed = dict(intent,subscription_epoch=2)
            with self.assertRaisesRegex(RuntimeError,'conflicting observation'):
                request(endpoint,self.identity,changed)
            child = subprocess.Popen(['/bin/cat'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,start_new_session=True)
            self.children.append(child)
            try:
                spawned = {'kind':'spawned','watch':'startup-late','launch':launch,
                           'pid':child.pid,'os_identity':capture(child.pid)}
                bad = dict(spawned,os_identity=dict(spawned['os_identity'],birth=[0,0]))
                with self.assertRaisesRegex(RuntimeError,'birth changed'):
                    request(endpoint,self.identity,bad)
                receipt = request(endpoint,self.identity,spawned)['receipt']
                self.assertEqual(request(endpoint,self.identity,spawned)['receipt'],receipt)
            finally:
                child.stdin.close()
                self.assertEqual(child.wait(timeout=2),0)
            deadline = time.monotonic()+2
            while True:
                item = request(endpoint,self.identity,{'kind':'lookup','watch':'startup-late'})['item']
                if item.get('owner_receipt'):
                    break
                self.assertLess(time.monotonic(),deadline,'public late owner discovery must remain additive')
                time.sleep(.002)
            self.assertEqual(item['owner'],owner_key(boundary.instance))
            self.assertNotIn('proof',item,'launcher exit never proves public owner lifetime')
            boundary.release_owner()
            deadline = time.monotonic()+2
            while True:
                item = request(endpoint,self.identity,{'kind':'lookup','watch':'startup-late'})['item']
                if item.get('proof'):
                    break
                self.assertLess(time.monotonic(),deadline,'real public proof after owner unlock')
                time.sleep(.002)
            closed = request(endpoint,self.identity,{'kind':'proof_custody_ack','watch':'startup-late',
                'path':item['proof']['path'],'sha256':item['proof']['sha256']})['consumer']
            request(endpoint,self.identity,{'kind':'retire','watch':'startup-late','sha256':closed['sha256']})
            request(endpoint,self.identity,{'kind':'retire_parent','parent':'startup-late'})
            request(endpoint,self.identity,{'kind':'finish'})


if __name__ == '__main__':
    unittest.main()
