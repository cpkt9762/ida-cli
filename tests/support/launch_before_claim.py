"""Test-only worker trampoline: delay exec until the private barrier releases."""
import os
from pathlib import Path
import sys
import time

barrier = Path(os.environ['R5_ROOT'])/'claim.release'
while not barrier.exists():
    time.sleep(.01)
os.execv(sys.argv[1], sys.argv[1:])
