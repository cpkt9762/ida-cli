"""Owner module inspection: exact code, ABI/defaults, sets and bindings.

This is a compatibility check in the accepted trusted-owner model. It does not
sandbox arbitrary code that can mutate Python/native introspection itself.
No inspected function or module-supplied digest function is ever called.
"""
import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import types

NAMES = ('_ida_cli_save_guard_v1', '_ida_cli_release_protocol_v1', '_ida_cli_nexus_slices_v1')
FILES = ('save_guard.py', 'lifecycle.py', 'slices.py')


def key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalized(value):
    if isinstance(value, types.CodeType):
        return {name: normalized(getattr(value, name)) for name in (
            'co_code', 'co_consts', 'co_names', 'co_varnames', 'co_freevars', 'co_cellvars',
            'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
            'co_stacksize', 'co_flags', 'co_exceptiontable')}
    if isinstance(value, types.FunctionType):
        return {'function_default': function(value)}
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, slice):
        return {'slice': [normalized(value.start), normalized(value.stop), normalized(value.step)]}
    if value is Ellipsis:
        return {'ellipsis': True}
    if isinstance(value, tuple):
        return {'tuple': [normalized(x) for x in value]}
    if isinstance(value, list):
        return {'list': [normalized(x) for x in value]}
    if isinstance(value, frozenset):
        return {'frozenset': sorted((normalized(x) for x in value), key=lambda x: json.dumps(x, sort_keys=True))}
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError('unsupported default mapping key')
        return {k: normalized(v) for k,v in value.items()}
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError('unsupported executable/default fingerprint value: ' + type(value).__name__)


def function(value):
    # Signature excludes repr(function), inspect's __signature__/__wrapped__
    # overrides and memory addresses. Defaults include executable function values.
    signature = inspect.Signature.from_callable(value, follow_wrapped=False)
    if '__signature__' in vars(value) or '__wrapped__' in vars(value):
        raise ValueError('unexpected signature override')
    parameters = []
    for parameter in signature.parameters.values():
        entry = {'name': parameter.name, 'kind': parameter.kind.name}
        if parameter.default is not inspect.Parameter.empty:
            entry['default'] = normalized(parameter.default)
        if parameter.annotation is not inspect.Parameter.empty:
            entry['annotation'] = normalized(parameter.annotation)
        parameters.append(entry)
    return {'code': key(normalized(value.__code__)), 'parameters': parameters,
            'defaults': normalized(value.__defaults__), 'kwdefaults': normalized(value.__kwdefaults__),
            'annotations': normalized(value.__annotations__),
            'closure': None if value.__closure__ is None else [normalized(c.cell_contents) for c in value.__closure__]}


def module_identity(value):
    name = value.__name__
    origin = getattr(value.__spec__, 'origin', None)
    if name in NAMES:
        source = {'kind': 'versioned-owner-module', 'version': 'v1'}
    elif origin in ('built-in', 'frozen'):
        source = {'kind': origin}
    elif origin and Path(origin).is_file():
        source = {'kind': 'file', 'sha256': hashlib.sha256(Path(origin).read_bytes()).hexdigest()}
    else:
        source = {'kind': 'unknown'}
    return {'name': name, 'registered': sys.modules.get(name) is value,
            'python_abi': list(sys.version_info[:3]), 'version': getattr(value, '__version__', None),
            'source': source}


def binding(value):
    module = sys.modules.get(value.__module__)
    exported = module
    for part in value.__qualname__.split('.'):
        exported = getattr(exported, part, None)
    return {'module': value.__module__, 'qualname': value.__qualname__, 'canonical_export': exported is value,
            'module_identity': module_identity(module) if module is not None else None}


def snapshot(modules, ida_version='9.5'):
    if set(modules) != set(NAMES):
        raise ValueError('incomplete v1 module set')
    result = {'schema': 2, 'python_abi': list(sys.version_info[:3]), 'ida': ida_version, 'modules': {}}
    for name, module in modules.items():
        values = vars(module)
        functions = {k: function(v) for k,v in values.items() if isinstance(v, types.FunctionType)}
        if any(v.__globals__ is not values or v.__module__ != name for v in values.values()
               if isinstance(v, types.FunctionType)):
            raise ValueError('foreign function/global binding')
        result['modules'][name] = {'identity': module_identity(module), 'functions': functions,
            'dependencies': {k: module_identity(v) if isinstance(v, types.ModuleType) else binding(v)
                for k,v in values.items() if isinstance(v, (types.ModuleType, type))}}
    guard = modules[NAMES[0]]
    hook = (guard._state or guard._failed_state).get('hook')
    if hook is None:
        raise ValueError('missing installed guard hook')
    result['modules'][NAMES[0]]['hook'] = {
        'functions': {k: function(v) for k,v in vars(type(hook)).items() if isinstance(v, types.FunctionType)},
        'bases': [[c.__module__, c.__name__] for c in type(hook).__mro__],
        'native_base': binding(type(hook).__mro__[1])}
    result['modules'][NAMES[2]]['live_counter'] = modules[NAMES[2]].counter is not None
    return result


LEGACY = {'ida': '9.5', 'modules': {'_ida_cli_nexus_slices_v1': {'dependencies': {'_release_module': {'name': '_ida_cli_release_protocol_v1', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'versioned-owner-module', 'version': 'v1'}, 'version': None}, 'sys': {'name': 'sys', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'built-in'}, 'version': None}, 'types': {'name': 'types', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '8c54d3d5ffc1d1204237e6c69b25c27c7b05b483128f185eeed9ba7ef2229ac2'}, 'version': None}, 'uuid': {'name': 'uuid', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '915321474fa4b27c3e289751e8ffc86e6a134b1244a37ca9053aeb2bf3c7e150'}, 'version': None}}, 'functions': {'cleanup_disconnected': {'annotations': {}, 'closure': None, 'code': 'f07babb18514c8671e04ba0f71fa2d0526c93fd0f3f0670d90a7e922b7d8e9d4', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'expected_incarnation'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'release_handle'}]}, 'install': {'annotations': {}, 'closure': None, 'code': '741c8986ebf4f59109585cbc7d23004fe248463c57775f5d663840aa641665ff', 'defaults': None, 'kwdefaults': None, 'parameters': []}, 'release': {'annotations': {}, 'closure': None, 'code': 'e7214aee08293eb7c3c6f0eb905faf7dc4e9e91ba75a7730ee9ae7dde5259863', 'defaults': {'tuple': [None]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'job'}, {'default': None, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}]}, 'release_lease': {'annotations': {}, 'closure': None, 'code': '435a2dea8094280e7f239e0941b83f68174922791bf2ffd9290c84dcfe7cb969', 'defaults': {'tuple': [None]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'default': None, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'expected_incarnation'}]}, 'stamp': {'annotations': {}, 'closure': None, 'code': '68c3e2682aa8177f47f41aaa49815bf552e3b973db325526c5d8056df41bf00a', 'defaults': None, 'kwdefaults': None, 'parameters': []}, 'step': {'annotations': {}, 'closure': None, 'code': 'e94ee3108c4467b521c56fd1045b4e7432a3bfaf6a7d311e739cfb7350856eb6', 'defaults': {'tuple': [None]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'method'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'params'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'decompile'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'parse_address'}, {'default': None, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'rename'}]}, 'uncertain': {'annotations': {}, 'closure': None, 'code': '89a56a48188858ca608b62a810913f56318cd08d385d656f66b138111e3486ba', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'detail'}]}, 'watch_lease': {'annotations': {}, 'closure': None, 'code': 'c07f104bc8b9487bb4433b2b28f50c72ea3c2d9c6c702b6a4c740566a5b6f0d0', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}]}}, 'identity': {'name': '_ida_cli_nexus_slices_v1', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'versioned-owner-module', 'version': 'v1'}, 'version': None}, 'live_counter': False}, '_ida_cli_release_protocol_v1': {'dependencies': {'Path': {'canonical_export': True, 'module': 'pathlib', 'module_identity': {'name': 'pathlib', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '042a4d0a5e1ef66778daa86dc269af205bd42d06e793e53d8b99dff4c45928ca'}, 'version': None}, 'qualname': 'Path'}, 'threading': {'name': 'threading', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '5323909624ec2165e70b6d31333e4191b63d383d2dc5a7d7d516a3475ea2b7e3'}, 'version': None}, 'time': {'name': 'time', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'built-in'}, 'version': None}}, 'functions': {'close_check': {'annotations': {}, 'closure': None, 'code': 'e06b3fb81ecac033be107c59804c55cad7631d52a5dadf115dda66a0a860fe54', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'deadline'}]}, 'database_diagnostics': {'annotations': {}, 'closure': None, 'code': '935639a77688583c1afc240c80b17a03e23f44297aff4c741656c54e9053ea79', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'path'}]}, 'release_errors': {'annotations': {}, 'closure': None, 'code': '35269fa7d1f48c29bae7de116c5d87019625b3b17e1933e5065c5a2a9de5961b', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}]}, 'release_group': {'annotations': {}, 'closure': None, 'code': '06472441fd0ca83f3be916207bdd5899c62f64a8d700805a85bdcd175e7da09e', 'defaults': {'tuple': [{'function_default': {'annotations': {}, 'closure': None, 'code': 'a5d5b9e29b446ee0aeac77f586a3c0526ec50d0e3bac7055e1ae56b5ae9f3674', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'VAR_POSITIONAL', 'name': '_'}]}}]}, 'kwdefaults': {'errors': {'tuple': []}}, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'participants'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'deadline'}, {'default': {'function_default': {'annotations': {}, 'closure': None, 'code': 'a5d5b9e29b446ee0aeac77f586a3c0526ec50d0e3bac7055e1ae56b5ae9f3674', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'VAR_POSITIONAL', 'name': '_'}]}}, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'publish'}, {'default': {'tuple': []}, 'kind': 'KEYWORD_ONLY', 'name': 'errors'}]}, 'release_handle': {'annotations': {}, 'closure': None, 'code': 'c480c54bcb30d33367f1c80fa56f963e11959a685f6be429eb72dffe7f98e2a4', 'defaults': {'tuple': [{'function_default': {'annotations': {}, 'closure': None, 'code': 'a5d5b9e29b446ee0aeac77f586a3c0526ec50d0e3bac7055e1ae56b5ae9f3674', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'VAR_POSITIONAL', 'name': '_'}]}}]}, 'kwdefaults': {'check': None, 'errors': {'tuple': []}, 'owner_proof': None, 'owner_required': False, 'request_only': False}, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'deadline'}, {'default': {'function_default': {'annotations': {}, 'closure': None, 'code': 'a5d5b9e29b446ee0aeac77f586a3c0526ec50d0e3bac7055e1ae56b5ae9f3674', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'VAR_POSITIONAL', 'name': '_'}]}}, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'publish'}, {'default': None, 'kind': 'KEYWORD_ONLY', 'name': 'check'}, {'default': {'tuple': []}, 'kind': 'KEYWORD_ONLY', 'name': 'errors'}, {'default': False, 'kind': 'KEYWORD_ONLY', 'name': 'owner_required'}, {'default': False, 'kind': 'KEYWORD_ONLY', 'name': 'request_only'}, {'default': None, 'kind': 'KEYWORD_ONLY', 'name': 'owner_proof'}]}, 'release_state': {'annotations': {}, 'closure': None, 'code': '0e1cc7612930e91d84944ef8b0c46084b652b2ff489718befa6d05c6dd3fa9ed', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}]}, 'same_owner': {'annotations': {}, 'closure': None, 'code': 'd922324888b26979c7f77da5297fba8962b6fdef7cbb32235d4ac69c4a0416d7', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'left'}, {'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'right'}]}, 'save_guard_error': {'annotations': {}, 'closure': None, 'code': 'ecfad9535841fd3016acbd56d5e600f17a2d45ead95945341a153c9c217648c2', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'handle'}]}}, 'identity': {'name': '_ida_cli_release_protocol_v1', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'versioned-owner-module', 'version': 'v1'}, 'version': None}}, '_ida_cli_save_guard_v1': {'dependencies': {'json': {'name': 'json', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '2dd10f1bf4c9ea5478e589216805e7f279d0e4bce134a19efa297404fb87407d'}, 'version': '2.0.9'}, 'logging': {'name': 'logging', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': 'e525bc1ea1744fca8d5a3d1639082eac53eaced7a8543691ceeae71649be0975'}, 'version': '0.5.1.2'}, 'os': {'name': 'os', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'frozen'}, 'version': None}, 'sys': {'name': 'sys', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'built-in'}, 'version': None}, 'time': {'name': 'time', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'built-in'}, 'version': None}}, 'functions': {'_database_flags': {'annotations': {}, 'closure': None, 'code': 'd81211fbfc332dc0cd53ef8230601690d1ac154b1ad503c5ba2a90b3a6f07ab8', 'defaults': None, 'kwdefaults': None, 'parameters': []}, '_delayed_probes': {'annotations': {}, 'closure': None, 'code': '753aa0f92a911499ef8a319d550a8184e7fcc2a5290d91fd3b3ff669fd25b5b6', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}]}, '_discard_on_close': {'annotations': {}, 'closure': None, 'code': 'bbdea06e5b20af9c2aec2bed5af7d569099d93eb91342c1c0ea4d27b1d5e8059', 'defaults': None, 'kwdefaults': None, 'parameters': []}, '_log': {'annotations': {}, 'closure': None, 'code': 'dbcd65624931b6f7702d5fe45c18bb4f68de361cd4d2bbbef01333cd526f26fe', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'value'}]}, '_metadata': {'annotations': {}, 'closure': None, 'code': 'bbd96b8296bb0c5dd1b4d83986d57ea91a7a55bb03b656b8a05a9c4c58b3b44f', 'defaults': None, 'kwdefaults': None, 'parameters': []}, '_optional': {'annotations': {}, 'closure': None, 'code': '8c840377066a5bf3c9de9ca48dd5bd4951d37ced49d6f6b297c7b2307b005636', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'function'}]}, 'begin': {'annotations': {}, 'closure': None, 'code': '157895e4b46b4a14d6ff0faf97dc1609ff3e6e903e59252d8ca69f15479d501c', 'defaults': {'tuple': [True]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'default': True, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'refuse'}]}, 'close_status': {'annotations': {}, 'closure': None, 'code': 'c65a5bfcdf7268e1abd503e99978b964bd7a6062c9f0d1a0105fe9309096a3d5', 'defaults': None, 'kwdefaults': None, 'parameters': []}, 'database_context': {'annotations': {}, 'closure': None, 'code': 'ba5a4a0e23cf285fdb1d361acd9064eb715ed29180f0db1dd9dde7e84a8e68f2', 'defaults': None, 'kwdefaults': None, 'parameters': []}, 'finish': {'annotations': {}, 'closure': None, 'code': '1864d85b29ec9ea89ae1220509e444b31ed55d20ccd67666111e7a6d5c704d2f', 'defaults': {'tuple': [True]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'default': True, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'refuse'}]}, 'install': {'annotations': {}, 'closure': None, 'code': '5bfe059f8fbac56f978301cd37e9ce4d5b31dcae2088b4c67e0a48fc5d7dc2cf', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}]}, 'sample': {'annotations': {}, 'closure': None, 'code': 'f3ff2430f16b7b6065a72db032a7496ad0f434495a6125317f80ecb7a177ad66', 'defaults': {'tuple': [None, True]}, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'stage'}, {'default': None, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'context'}, {'default': True, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'refuse'}]}, 'save_database': {'annotations': {}, 'closure': None, 'code': 'ec405fb0cdd96ed09a844267848c923bc310de53961d4196047e8098ffecb93e', 'defaults': {'tuple': [None, 0]}, 'kwdefaults': None, 'parameters': [{'default': None, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'outfile'}, {'default': 0, 'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'flags'}]}}, 'hook': {'bases': [['_ida_cli_save_guard_v1', 'CloseGuard'], ['ida_idp', 'IDB_Hooks'], ['builtins', 'object']], 'functions': {'closebase': {'annotations': {}, 'closure': None, 'code': 'c60698c205c56582d034f8e9bebb021e5c53dc7c56bf33738ec27d6616a9edbb', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'self'}]}, 'savebase': {'annotations': {}, 'closure': None, 'code': '2bc201566b8f3eae7c4a286aab05a80db68187c91bab7a6e96e99ee646ece411', 'defaults': None, 'kwdefaults': None, 'parameters': [{'kind': 'POSITIONAL_OR_KEYWORD', 'name': 'self'}]}}, 'native_base': {'canonical_export': True, 'module': 'ida_idp', 'module_identity': {'name': 'ida_idp', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'file', 'sha256': '4d3eda8f55507d11d659fec5b1c21b26a5c0bcffe8de3af51618a9e8fb7d0e2b'}, 'version': None}, 'qualname': 'IDB_Hooks'}}, 'identity': {'name': '_ida_cli_save_guard_v1', 'python_abi': [3, 14, 7], 'registered': True, 'source': {'kind': 'versioned-owner-module', 'version': 'v1'}, 'version': None}}}, 'python_abi': [3, 14, 7], 'schema': 2}


def current_module(name, source, actual):
    expected = types.ModuleType(name)
    if name == NAMES[2]:
        if NAMES[1] not in sys.modules:
            raise ValueError('missing slices release dependency')
        vars(expected).update(sys=sys, types=types,
            _release_module=sys.modules.get(NAMES[1]))
    exec(compile(source, '<known-current-owner>', 'exec'), vars(expected))
    def describe(module):
        values = vars(module)
        functions = {k:function(v) for k,v in values.items() if isinstance(v, types.FunctionType)}
        if any(v.__globals__ is not values or v.__module__ != name for v in values.values()
               if isinstance(v, types.FunctionType)):
            raise ValueError('foreign function/global binding: '+name)
        dependencies = {k:module_identity(v) if isinstance(v, types.ModuleType) else binding(v)
            for k,v in values.items() if isinstance(v,(types.ModuleType,type))}
        constants = {k:normalized(v) for k,v in values.items() if k.isupper()}
        return {'functions':functions, 'dependencies':dependencies, 'constants':constants}
    if sys.modules.get(name) is not actual or actual.__name__ != name:
        raise ValueError('owner module registration changed: '+name)
    if describe(actual) != describe(expected):
        return False
    if name != NAMES[0]:
        return True
    state = vars(actual).get('_state') or vars(actual).get('_failed_state')
    hook = state.get('hook') if isinstance(state,dict) else None
    if hook is None:
        return True  # Fresh install/known failed install; fresh guard still decides protection.
    import ida_idp
    tree = ast.parse(source)
    install = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == 'install')
    hook_class = next(n for n in install.body if isinstance(n,ast.ClassDef))
    factory = ast.FunctionDef(name='install', args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],
        kw_defaults=[],defaults=[]), body=[hook_class,
        ast.Return(value=ast.Name(id='CloseGuard',ctx=ast.Load()))], decorator_list=[])
    namespace = {'__name__':name,'ida_idp':ida_idp}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[factory],type_ignores=[])),
        '<known-current-hook>','exec'), namespace)
    known = namespace['install']()
    observed = type(hook)
    actual_functions = {k:function(v) for k,v in vars(observed).items() if isinstance(v,types.FunctionType)}
    known_functions = {k:function(v) for k,v in vars(known).items() if isinstance(v,types.FunctionType)}
    return (observed.__bases__ == known.__bases__ and actual_functions == known_functions
        and all(v.__globals__ is vars(actual) for v in vars(observed).values() if isinstance(v,types.FunctionType)))


def classify(sources, *, cleanup):
    present = {name:sys.modules[name] for name in NAMES if name in sys.modules}
    try:
        if all(current_module(name,sources[name],module) for name,module in present.items()):
            return 'current'
        import ida_kernwin
        actual = snapshot(present, ida_kernwin.get_kernel_version())
        if actual == LEGACY:
            if cleanup:
                return 'known_v1_cleanup_only'
            raise ValueError('known v1 permits cleanup only; no preparation or business')
        raise ValueError('unknown owner module combination')
    except Exception as exc:
        raise RuntimeError('ProtocolMismatch/CleanupBlocked: '+str(exc)+
            '; next_action=explicit_offline_maintenance_or_authorized_bridge_shutdown; '
            'exact lease and observation retained') from exc
