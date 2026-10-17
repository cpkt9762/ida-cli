"""Externally supplied v1 inspector: exact code, ABI/defaults, sets and bindings.

This is a compatibility check in the accepted trusted-owner model. It does not
sandbox arbitrary code that can mutate Python/native introspection itself.
No inspected function or module-supplied digest function is ever called.
"""
import ast
from contextlib import contextmanager
import hashlib
import importlib.machinery
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


def validate(actual, expected):
    # Whole-object equality checks complete function/hook/dependency sets, every
    # ABI/default, and each binding/version. No subset all() acceptance.
    if actual != expected:
        raise ValueError('unknown v1 compatibility combination')
    return key(actual)


@contextmanager
def known_modules(repo, ida_root):
    """Execute only pinned local source; synthesize just the known hook class.

    No IDA call/installation is executed locally. The native base's installed
    file is pinned read-only, while the owner must export the actual base.
    """
    saved = {name: sys.modules.get(name) for name in (*NAMES, 'ida_idp')}
    modules = {name: types.ModuleType(name) for name in NAMES}
    native = types.ModuleType('ida_idp')
    native.__spec__ = importlib.machinery.ModuleSpec('ida_idp', None,
        origin=str(Path(ida_root) / 'python/ida_idp.py'))
    native.IDB_Hooks = type('IDB_Hooks', (), {'__module__': 'ida_idp'})
    sys.modules.update(modules, ida_idp=native)
    try:
        sources = {name: (Path(repo) / 'nexus_bridge' / filename).read_text()
                   for name, filename in zip(NAMES, FILES)}
        for name in NAMES:
            if name == NAMES[2]:
                vars(modules[name]).update(sys=sys, types=types, _release_module=modules[NAMES[1]])
            exec(compile(sources[name], '<known-v1>', 'exec'), vars(modules[name]))
        tree = ast.parse(sources[NAMES[0]])
        install = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'install')
        hook_class = next(n for n in install.body if isinstance(n, ast.ClassDef))
        namespace = {'__name__': NAMES[0], 'ida_idp': native}
        # Retain its original nesting/CO_NESTED; moving the class to module
        # scope would change executable flags and correctly fail a real match.
        factory = ast.FunctionDef(name='install', args=ast.arguments(posonlyargs=[], args=[],
            kwonlyargs=[], kw_defaults=[], defaults=[]), body=[hook_class,
            ast.Return(value=ast.Name(id='CloseGuard', ctx=ast.Load()))], decorator_list=[])
        factory_tree = ast.fix_missing_locations(ast.Module(body=[factory], type_ignores=[]))
        exec(compile(factory_tree, '<known-hook>', 'exec'), namespace)
        modules[NAMES[0]]._state = {'hook': namespace['install']()()}
        yield modules
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def expected_snapshot(repo, ida_root):
    with known_modules(repo, ida_root) as modules:
        return snapshot(modules)
