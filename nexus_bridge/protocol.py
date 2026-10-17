"""R5 admission contract. Future custody/helper families remain unavailable."""
import json
import os

HANDLE_SHA = 'aa5d7ea42caaa922ef494d7d8a1406396537a4ea88d9e833825e08c8d279025e'


def contract():
    return {'wire': 2, 'schema': 1, 'release': 1, 'open': 1,
            'owner_observation': 0, 'client_hash': HANDLE_SHA,
            'capabilities': ['absolute_home_v1', 'lifetime_handshake_v1',
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
