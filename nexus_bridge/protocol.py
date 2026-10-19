"""Exact adapter versions; boot retirement still requires a qualified native scope."""
import json
import os

SDK_FILES = {'handle.py': 'dd9daf669b6dc55f657dd11b60f9869dcca70cf278cc65bc1d91b4e02b199acd', '_resolver.py': 'd06a1014c2193a50372f24144200949092cbead48ffd7113221fa7220e9733e8', 'options.py': '1fbd67a12adee065b8db6fa97a333130986085ccedc7728ba92cb41fa3d9dcfe'}
HANDLE_SHA = SDK_FILES['handle.py']


def verify_client():
    """The prepared SDK is the same fixed dependency in bridge and maintenance."""
    import hashlib
    import importlib
    import importlib.metadata
    from pathlib import Path
    import ida_nexus
    versions=[importlib.metadata.version(name) for name in ('ida-nexus','ida-domain')]
    if versions != ['0.13.4','0.5.1']:
        raise ValueError('ProtocolMismatch: fixed Nexus 0.13.4/Domain 0.5.1 required')
    package=Path(ida_nexus.__file__).resolve().parent
    modules={}
    for name,expected in SDK_FILES.items():
        module=importlib.import_module('ida_nexus.'+name.removesuffix('.py'))
        source=Path(module.__file__).resolve()
        actual=hashlib.sha256(source.read_bytes()).hexdigest()
        if source != package/name or actual != expected:
            raise ValueError('ProtocolMismatch: incompatible SDK module '+name)
        modules[name]={'path':str(source),'sha256':actual}
    return modules


def contract():
    return {'wire': 2, 'schema': 1, 'release': 4, 'open': 4,
            'owner_observation': 1, 'custody':5, 'helper':2, 'target_gate':2,
            'same_boot_exit':0, 'boot_retirement':1, 'client_hash': HANDLE_SHA,
            'sdk_boundary': 2, 'client_modules': dict(SDK_FILES),
            'capabilities': ['absolute_home_v1', 'ack_cleanup_v1', 'acquisition_outcome_v1',
                             'durable_public_proof_v1', 'file_job_relay_v1', 'file_recovery_ack_v1', 'final_preparing_v1', 'internal_grant_v1', 'k2_acquisitions_v1',
                             'launch_observer_v1', 'lifetime_handshake_v1',
                             'receiver_isolation_v1', 'release_observation_v1', 'retired_release_observation_v1', 'single_resolution_outcome_v1', 'target_gate_base_v1', 'two_phase_release_v1', 'unstarted_absence_v1', 'verification_removal_v1']}


def validate(value):
    # Compare capability sets without accepting duplicates or partial upgrades.
    if (isinstance(value, dict) and isinstance(value.get('capabilities'), list)
            and all(isinstance(item, str) for item in value['capabilities'])):
        value = dict(value, capabilities=sorted(value['capabilities']))
    if json.dumps(value, sort_keys=True) != json.dumps(contract(), sort_keys=True):
        raise ValueError('ProtocolMismatch: incompatible Nexus adapter contract')


def admission():
    expected = os.environ.get('IDA_CLI_NEXUS_PROTOCOL')
    if expected is not None:
        validate(json.loads(expected))
    return contract()
