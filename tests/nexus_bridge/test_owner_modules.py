"""Inspect loaded owner code without invoking untrusted code or its reports."""
from pathlib import Path
import os
import sys
import types
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge'), str(REPO/'nexus_bridge/custody'), str(REPO/'tests/support')]
from owner_modules import classify, NAMES, FILES
from r0_transport import install_ida_inputs

SOURCES = {name:(REPO/'nexus_bridge'/file).read_text() for name,file in zip(NAMES, FILES)}


class OwnerModules(unittest.TestCase):
    def setUp(self):
        self.saved = dict(sys.modules)
        for name in NAMES:
            sys.modules.pop(name, None)
        path = Path(os.environ['R3A_CASE_ROOT'])/'owner-module-model.i64'
        path.write_bytes(b'private native input model')
        install_ida_inputs(path)

    def tearDown(self):
        for name in (*NAMES, *(n for n in sys.modules if n.startswith('ida_'))):
            if name in self.saved:
                sys.modules[name] = self.saved[name]
            else:
                sys.modules.pop(name, None)

    def install(self):
        for name in NAMES:
            module = types.ModuleType(name)
            if name == NAMES[2]:
                vars(module).update(sys=sys, types=types, _release_module=sys.modules[NAMES[1]])
            exec(compile(SOURCES[name], '<current-owner>', 'exec'), vars(module))
            sys.modules[name] = module
        sys.modules[NAMES[0]].begin({'record_id':'private-model'})
        return sys.modules[NAMES[0]],sys.modules[NAMES[1]],sys.modules[NAMES[2]]

    def test_fresh_and_loaded_current_with_installed_hook(self):
        self.assertEqual(classify(SOURCES,cleanup=False),'current')
        self.install()
        self.assertEqual(classify(SOURCES,cleanup=False),'current')
        self.assertEqual(classify(SOURCES,cleanup=True),'current')

    def test_changed_code_signature_defaults_dependencies_and_hook_never_execute(self):
        for fault in ('code','parameter','default','dependency','hook','extra','constant','missing'):
            with self.subTest(fault=fault):
                guard,release,slices = self.install()
                marker = []
                def unknown(*args,**kwargs):
                    marker.append('unsafe')
                    raise AssertionError('unknown inspected code executed')
                if fault == 'code':
                    namespace = {}
                    exec("def changed():\n    raise AssertionError('unknown code executed')",namespace)
                    guard.close_status.__code__ = namespace['changed'].__code__
                elif fault == 'parameter':
                    guard.close_status = unknown
                elif fault == 'default':
                    guard.begin.__defaults__ = (False,)
                elif fault == 'dependency':
                    guard.time = types.ModuleType('foreign_time')
                elif fault == 'hook':
                    type(guard._state['hook']).closebase = unknown
                elif fault == 'extra':
                    slices.report_digest = unknown
                elif fault == 'constant':
                    slices.NOTIFICATIONS = ()
                else:
                    del release.release_handle
                for cleanup in (False,True):
                    with self.assertRaisesRegex(RuntimeError,'ProtocolMismatch/CleanupBlocked'):
                        classify(SOURCES,cleanup=cleanup)
                self.assertEqual(marker,[])

    def test_foreign_global_binding_and_incomplete_unknown_combination_rejected(self):
        guard,release,slices = self.install()
        guard.close_status = types.FunctionType(guard.close_status.__code__,dict(vars(guard)))
        with self.assertRaisesRegex(RuntimeError,'foreign function/global binding'):
            classify(SOURCES,cleanup=True)
        sys.modules.pop(NAMES[1])
        sys.modules.pop(NAMES[2])
        with self.assertRaisesRegex(RuntimeError,'CleanupBlocked'):
            classify(SOURCES,cleanup=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
