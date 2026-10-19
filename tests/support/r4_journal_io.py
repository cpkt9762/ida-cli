"""Production writer entry with one exact routine unlink errno input."""
import errno
import os
from pathlib import Path
import sys

repo=Path(sys.argv[1])
sys.path[:0]=[str(repo/'nexus_bridge/custody'),str(repo/'nexus_bridge')]
import target_journal

actual=os.unlink
def unlink(name,*args,**kwargs):
    if name=='routine-denied.json':
        raise OSError(errno.EACCES,'controlled closed-routine unlink refusal')
    return actual(name,*args,**kwargs)
target_journal.os.unlink=unlink
target_journal.main()
