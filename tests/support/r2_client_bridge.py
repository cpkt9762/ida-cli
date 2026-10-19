"""Second router uses the production bridge and the first private input owner."""
import os
from pathlib import Path
import runpy
import sys
from r2_process_ledger import install
install()

installation = Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
sys.argv = [str(installation/'bootstrap.py'), 'bridge', *sys.argv[1:]]
entry = runpy.run_path(sys.argv[0], run_name='verified_fixture')['load_entry']()
if os.environ.get('R6_CAPABILITY_TRACE'):
    import json
    import ida_nexus
    trace=Path(os.environ['R6_CAPABILITY_TRACE'])
    def observed(name, actual):
        def call(*args, **kwargs):
            with trace.open('a') as output:output.write(json.dumps({'sdk_call':name})+'\n')
            return actual(*args, **kwargs)
        return call
    ida_nexus.probe_database_state=observed('probe_database_state',ida_nexus.probe_database_state)
    for name in ('open_outcome','resolve_outcome','attach_outcome'):
        setattr(ida_nexus.DatabaseHandle,name,observed(name,getattr(ida_nexus.DatabaseHandle,name)))
    if os.environ.get('R6_CAPABILITY_FAULT')=='1':
        import errno
        import recovery_files
        def unsupported(*_args, **_kwargs):
            raise OSError(errno.ENOTSUP,'public filesystem exception injection')
        recovery_files.rename_noreplace=unsupported
entry.main()
