"""Startup paths: mirror idb_store::ida_home; Nexus owns its state rules."""
import os
from pathlib import Path


def ida_cli_home(environment=None, cwd=None):
    environment = os.environ if environment is None else environment
    explicit = environment.get('IDA_CLI_HOME')
    home = Path(explicit) if explicit else Path(environment.get('HOME', '/tmp')) / '.ida'
    # Deliberately do not expand '~'. Empty HOME means the startup CWD.
    return (Path.cwd() / home if cwd is None else Path(cwd) / home).absolute()


def startup_paths():
    """Freeze before importing Nexus (its registry root is import-time state)."""
    home = ida_cli_home()
    os.environ['IDA_CLI_HOME'] = str(home)
    from ida_nexus import get_state_dir
    state = Path(get_state_dir()).absolute()
    os.environ['IDA_NEXUS_STATE_DIR'] = str(state)
    return {'ida_cli_home': str(home), 'state_dir': str(state)}
