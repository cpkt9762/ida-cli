"""Actual create-before-binding exits retain unpublished bytes and resume."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]


def action(root,kind,crash):
    from target_coordination import Directory
    from recovery_files import copy_exact,file_info
    actual=os.open
    def intercepted(name,flags,*args,**kwargs):
        fd=actual(name,flags,*args,**kwargs)
        # The first owned file creation is the precise unbound-create window.
        if flags & os.O_EXCL and crash:
            (root/'created.json').write_text(json.dumps({'name':str(name),'inode':os.fstat(fd).st_ino}))
            os._exit(97)
        return fd
    directory=Directory(root/'destination')
    source=Directory(root/'source')
    try:
        os.open=intercepted
        if kind=='record':directory.durable('custody.json',{'known':'complete requested bytes'})
        else:
            path=root/'binding.json'
            binding=json.loads(path.read_text()) if path.exists() else None
            def checkpoint(value):
                path.write_text(json.dumps(value))
                with path.open() as stream:os.fsync(stream.fileno())
            copy_exact(source,'input.i64',directory,file_info(source,'input.i64'),0o400,
                       binding,checkpoint,directory.verify)
    finally:
        os.open=actual
        directory.close();source.close()


class UnpublishedCreation(unittest.TestCase):
    def test_fresh_process_resumes_after_real_unbound_creation(self):
        root=Path(tempfile.mkdtemp(prefix='unbound-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        for kind in ('record','copy'):
            with self.subTest(kind=kind):
                case=root/kind;case.mkdir(mode=0o700)
                for name in ('destination','source'):(case/name).mkdir(mode=0o700)
                (case/'source/input.i64').write_bytes(b'complete original'*100)
                (case/'source/input.i64').chmod(0o600)
                results=[]
                for crash,expected in ((True,97),(False,0)):
                    argv=['timeout','10s',sys.executable,'-B',__file__,'--child',str(case),kind,str(int(crash))]
                    uptime=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
                    result=subprocess.run(argv,capture_output=True,text=True)
                    results.append(dict(argv=argv,exit=result.returncode,stderr=result.stderr,uptime=uptime))
                    (case/'runs.json').write_text(json.dumps(results,indent=2))
                    self.assertEqual(result.returncode,expected,result.stderr)
                created=json.loads((case/'created.json').read_text())
                # The unbound inode survives as retained evidence, never read
                # as authority and never removed to make the test pass.
                self.assertEqual((case/'destination'/created['name']).stat().st_ino,created['inode'])
                if kind=='record':self.assertEqual(json.loads((case/'destination/custody.json').read_text()),{'known':'complete requested bytes'})
                else:self.assertEqual((case/'destination/input.i64').read_bytes(),(case/'source/input.i64').read_bytes())


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':action(Path(sys.argv[2]),sys.argv[3],bool(int(sys.argv[4])))
    else:unittest.main(verbosity=2)
