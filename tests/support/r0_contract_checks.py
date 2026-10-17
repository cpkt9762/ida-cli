"""Negative contract checks: OS/boot inputs never complete N1 history."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/nexus'))
from r0_contract import consumer_policy, effects_for, validate_message_contract
from r0_common import durable


def contract():
    policy = consumer_policy()
    return {'kinds': list(policy), 'payloads': {k: {'scope': v['scope']} for k,v in policy.items()},
            'consumer_policy': policy}


class ContractPrototypes(unittest.TestCase):
    def test_scopes_have_disjoint_consumers(self):
        value = contract()
        self.assertEqual(effects_for(value, 'owner_released', 'public_owner_lifetime', 'N1'), ('owner_released',))
        for kind in ('owner_exit_observed', 'resource_retired'):
            scope = value['payloads'][kind]['scope']
            with self.assertRaises(ValueError):
                effects_for(value, kind, scope, 'N1')
            self.assertTrue(effects_for(value, kind, scope, 'Tools'))
        with self.assertRaises(ValueError):
            effects_for(value, 'owner_released', 'eligible_same_boot_os_exit', 'N1')
        path = Path(os.environ['R0_CASE_ROOT'])
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        durable(path / 'scope-results.json', {'policy': value, 'OS_to_N1_rejected': True,
                'boot_to_N1_rejected': True, 'scope': 'R0-contract-only'})

    def test_freezer_rejects_union_scope_and_widened_effects(self):
        for mutation in ('union', 'consumer', 'effect', 'missing'):
            value = deepcopy(contract())
            if mutation == 'union':
                value['payloads']['owner_released']['scope'] += '|eligible_same_boot_os_exit'
            elif mutation == 'consumer':
                value['consumer_policy']['owner_exit_observed']['consumers']['N1'] = ['owner_released']
            elif mutation == 'effect':
                value['consumer_policy']['resource_retired']['consumers']['Tools'].append('N1.execution_stopped')
            else:
                value['kinds'].remove('owner_exit_observed')
            with self.assertRaises(ValueError, msg=mutation):
                validate_message_contract(value)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        validate_message_contract(json.loads(Path(sys.argv[1]).read_text())['message_contract'])
    else:
        unittest.main(verbosity=2)
