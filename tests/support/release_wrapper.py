"""Per-member Python wrapper double; never supplies N1 phases or owner proofs.

Production authority/transport/helper coverage lives in nexus_r3b.rs. This
fixture isolates actual guard sampling, pinned SDK outcomes and one-shot calls.
"""
import concurrent.futures
import threading
import uuid


class CustodyBoundary:
    def __init__(self, bridge, lease, handle):
        self.bridge, self.lease, self.handle = bridge, lease, handle
        self.acquisition = {'parent':{'operation_id':'wrapper-only'}, 'purpose':'auxiliary', 'ordinal':1}
        self.owner, self.watch = {'record_id':handle.instance.record_id}, uuid.uuid4().hex
        self.release_event = threading.Event()
        self.auxiliary_custody = None

    def cleanup(self):
        pass  # Authority boundary double; no fake N1 transition is produced.

    def execute(self, _purpose, code, **_options):
        return self.handle.execute_python(code, operation_id='wrapper-'+uuid.uuid4().hex)

    def auxiliary(self, _deadline):
        if self.auxiliary_custody is None:
            raise AssertionError('wrapper has no physical auxiliary input')
        child = self.auxiliary_custody
        self.bridge.handles[child.lease['lease_id']] = (child.lease, child.handle)
        self.bridge.custodians[child.lease['lease_id']] = child
        self.bridge.cleanup_handles[self.lease['lease_id']] = child
        return child

    def transact(self, action, **fields):
        assert action == 'release_observation', 'wrapper is not a custody authority'
        self.bridge.wrapper_preflights.append(fields)
        return {'ok':True}


def install(bridge, lease, primary, auxiliary=None):
    bridge.wrapper_preflights = []
    if not hasattr(bridge, 'detach_pool'):
        bridge.detach_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    primary_custody = CustodyBoundary(bridge, lease, primary)
    bridge.custodians[lease['lease_id']] = primary_custody
    child = None
    if auxiliary is not None:
        auxiliary_lease = dict(lease, lease_id=lease['lease_id']+'-aux')
        child = CustodyBoundary(bridge, auxiliary_lease, auxiliary)
        child.cleanup_context = [bridge.identity,lease['lease_id'],lease['instance_id'],lease['generation'],bridge.lifetime_path]
        primary_custody.auxiliary_custody = child
    return primary_custody, child
