"""R5 admission contract. Future custody/helper families remain unavailable."""
import json
import os

SDK_FILES = {'handle.py': '93eb5a03ab46f4f1d0aedc12ecdd5b9f22a966ad748bc3a1fd05adfd163d2432', '_resolver.py': 'd06a1014c2193a50372f24144200949092cbead48ffd7113221fa7220e9733e8', 'options.py': '1fbd67a12adee065b8db6fa97a333130986085ccedc7728ba92cb41fa3d9dcfe'}
HANDLE_SHA = SDK_FILES['handle.py']


def contract():
    return {'wire': 2, 'schema': 1, 'release': 1, 'open': 1,
            'owner_observation': 0, 'client_hash': HANDLE_SHA,
            'sdk_boundary': 1, 'client_modules': dict(SDK_FILES),
            'capabilities': ['absolute_home_v1', 'ack_cleanup_v1', 'acquisition_outcome_v1',
                             'launch_observer_v1', 'lifetime_handshake_v1',
                             'receiver_isolation_v1', 'release_observation_v1']}


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
