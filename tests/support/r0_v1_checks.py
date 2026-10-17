"""Stable independent-interpreter keys and complete v1 mutation rejection."""
from copy import deepcopy
import os
from pathlib import Path
import sys
import types
import unittest

from r0_common import durable, fork, read
from r0_v1 import NAMES, expected_snapshot, known_modules, snapshot, validate

REPO = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ['R0_CASE_ROOT'])
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
IDA = Path(os.environ['R0_IDA_ROOT'])


class V1Prototypes(unittest.TestCase):
    def test_independent_interpreters_produce_same_full_key(self):
        results = []
        for index in range(2):
            output = ROOT / f'interpreter-{index}.json'
            pid = fork()
            if pid == 0:
                os.execv(sys.executable, [sys.executable, '-B', __file__, '--snapshot', str(output)])
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
            results.append(read(output))
        self.assertEqual(results[0], results[1], 'same source in independent interpreters must have identical ABI/defaults/key')
        self.assertEqual(validate(results[0]['snapshot'], expected_snapshot(REPO, IDA)), results[0]['key'])

    def test_all_functions_defaults_hooks_and_bindings_checked(self):
        expected = expected_snapshot(REPO, IDA)
        rows = []
        for case in ('missing-function', 'extra-function', 'sample-refuse', 'request-only',
                     'function-default', 'dependency', 'imported-class', 'missing-hook', 'extra-hook'):
            with self.subTest(case=case), known_modules(REPO, IDA) as modules:
                guard, release = modules[NAMES[0]], modules[NAMES[1]]
                if case == 'missing-function':
                    del release.close_check
                elif case == 'extra-function':
                    exec('def extra(): return None', vars(release))
                elif case == 'sample-refuse':
                    guard.sample.__defaults__ = (None, False)
                elif case == 'request-only':
                    release.release_handle.__kwdefaults__['request_only'] = True
                elif case == 'function-default':
                    exec('def altered(*args): return True', vars(release))
                    release.release_handle.__defaults__ = (release.altered,)
                    del release.altered
                elif case == 'dependency':
                    release.threading = types.ModuleType('unexpected_threading')
                elif case == 'imported-class':
                    release.Path = str
                elif case == 'missing-hook':
                    del type(guard._state['hook']).savebase
                else:
                    exec('def extra(self): return 0', vars(guard))
                    type(guard._state['hook']).extra = guard.extra
                    del guard.extra
                actual = snapshot(modules)
                with self.assertRaises(ValueError, msg=case):
                    validate(actual, expected)
                rows.append({'mutation': case, 'rejected': True})
        # Also verify complete module set and runtime dependency version fields.
        for case in ('module-set', 'dependency-version', 'parameter-kind', 'ida-version'):
            actual = deepcopy(expected)
            if case == 'module-set':
                del actual['modules'][NAMES[1]]
            elif case == 'dependency-version':
                actual['modules'][NAMES[1]]['dependencies']['threading']['python_abi'][1] += 1
            elif case == 'parameter-kind':
                actual['modules'][NAMES[1]]['functions']['release_handle']['parameters'][0]['kind'] = 'KEYWORD_ONLY'
            else:
                actual['ida'] = 'unrecognized-runtime'
            with self.assertRaises(ValueError):
                validate(actual, expected)
            rows.append({'mutation':case, 'rejected':True})
        durable(ROOT / 'v1-results.json', {'key': validate(expected, expected), 'checks':rows,
            'comparison':'complete equality of module/function/hook/ABI/default/dependency objects',
            'trust_scope':'known trusted-owner compatibility, not arbitrary code sandbox'})


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--snapshot':
        value = expected_snapshot(REPO, IDA)
        durable(Path(sys.argv[2]), {'key': validate(value, value), 'snapshot': value})
    else:
        unittest.main(verbosity=2)
