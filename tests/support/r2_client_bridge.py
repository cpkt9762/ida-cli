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
entry.main()
