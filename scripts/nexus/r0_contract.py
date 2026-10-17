"""R0-only scope/consumer policy; never a production N1 event receiver."""
from copy import deepcopy

POLICY = {
    'owner_released': {
        'scope': 'public_owner_lifetime',
        'consumers': {'N1': ['owner_released'], 'Tools': ['owner_exit', 'owner_guard', 'file_guard']},
        'forbidden': ['synthesize_ack', 'rewrite_business_result'],
    },
    'owner_exit_observed': {
        'scope': 'eligible_same_boot_os_exit',
        'consumers': {'Tools': ['owner_exit', 'startup_exit', 'owner_guard', 'file_guard']},
        'forbidden': ['N1.owner_released', 'N1.Released', 'N1.execution_stopped',
                      'lease_detached', 'synthesize_ack', 'rewrite_business_result'],
    },
    'resource_retired': {
        'scope': 'verified_boot_change_resource_retirement',
        'consumers': {'Tools': ['old_boot_live_capacity', 'old_boot_guards', 'resource_liveness']},
        'forbidden': ['N1.owner_released', 'N1.Released', 'N1.execution_stopped',
                      'lease_detached', 'synthesize_ack', 'rewrite_business_result'],
    },
}


def consumer_policy():
    return deepcopy(POLICY)


def validate_message_contract(contract):
    """Fail closed on widened scopes/effects, including old union-scope freezes."""
    if contract.get('consumer_policy') != POLICY:
        raise ValueError('scope/consumer policy differs from accepted R0 boundary')
    for kind, rule in POLICY.items():
        if contract['payloads'][kind]['scope'] != rule['scope']:
            raise ValueError('invalid scope for ' + kind)
        if kind not in contract['kinds']:
            raise ValueError('missing scope-isolated event: ' + kind)
    return True


def effects_for(contract, kind, scope, consumer):
    validate_message_contract(contract)
    rule = contract['consumer_policy'][kind]
    if scope != rule['scope'] or consumer not in rule['consumers']:
        raise ValueError('forbidden evidence consumer')
    return tuple(rule['consumers'][consumer])
