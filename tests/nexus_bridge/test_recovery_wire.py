"""Real SCM job packets stay bounded; full diagnostics remain durable.

Owner absence is a controlled component input. Actual IDA is covered separately.
"""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]
from test_recovery_transaction import setup,isolate_owner_input,no_owner_input
from target_coordination import Target
from recovery_transaction import Transaction
from recovery_transfer import FrozenOffer,receive
from recovery_job import completed,validate_ready


class WireReceipts(unittest.TestCase):
    def setUp(self):isolate_owner_input(self)

    def test_large_cause_and_unicode_paths_use_small_exact_receipts_and_reject_tampering(self):
        base=Path(tempfile.mkdtemp(prefix='bounded-wire-',dir=os.environ['R3A_CASE_ROOT']))
        case=base/('long-'+'a'*160)/('unicode-'+'中'*24)
        case.mkdir(mode=0o700,parents=True)
        setup(case)
        reference=json.loads((case/'reference.json').read_text())
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        a.settimeout(5)
        process=subprocess.Popen(['timeout','12s',sys.executable,'-B',__file__,'--receiver',
            str(b.fileno()),str(case/'reference.json')],pass_fds=(b.fileno(),),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        b.close()
        lengths=[]
        class Captured:
            def recvmsg(self,*args):
                result=a.recvmsg(*args)
                lengths.append(len(result[0]))
                return result
        try:
            with Target(reference['target']) as target,target.locked():
                with Transaction(target,reference['recovery_id']) as transaction:
                    transaction.resume_executor()
                    transaction.data['cause']={'code':'operation_failed','message':'full diagnostic '*5000}
                    transaction.save()
                    hello,_=receive(Captured(),0)
                    validate_ready(hello,transaction)
                    offer=FrozenOffer(transaction,hello['actor'])
                    offer.send(a)
                    accepted,_=receive(Captured(),0)
                    self.assertTrue(accepted['accepted'])
                    receipt,_=receive(Captured(),0)
                    before=(transaction.directory.path/'recovery.json').read_bytes()
                    for key,value in (('schema',1),('epoch',True),('transfer_id','0'*32),
                        ('record_sha256','0'*64),('binding_sha256','0'*64),('revision',True),('error',None)):
                        with self.subTest(field=key):
                            bad=copy.deepcopy(receipt)
                            bad[key]=value
                            with self.assertRaisesRegex(RuntimeError,'HandoffBlocked'):completed(transaction,offer.binding,bad)
                            self.assertEqual((transaction.directory.path/'recovery.json').read_bytes(),before)
                    result=completed(transaction,offer.binding,receipt)
                    self.assertEqual(result['status']['phase'],'restored')
                    self.assertEqual(len(result['status']['cause']['message']),len('full diagnostic '*5000))
                    self.assertTrue(all(size<1536 for size in lengths),lengths)
                    self.assertNotIn('status',receipt,'full status must never enter a datagram')
            stdout,stderr=process.communicate(timeout=5)
            (case/'process.json').write_text(json.dumps({'exit':process.returncode,'stdout':stdout,'stderr':stderr,
                'packet_bytes':lengths,'scope':'actual kernel SCM/job, controlled absent-owner input'}))
            self.assertEqual(process.returncode,0,stderr)
        finally:
            a.close()
            if process.poll() is None:process.communicate(timeout=15)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--receiver':
        no_owner_input()
        from recovery_job import execute
        reference=json.loads(Path(sys.argv[3]).read_text())
        with socket.socket(fileno=int(sys.argv[2])) as channel:
            channel.settimeout(5)
            raise SystemExit(execute(channel,reference['target'],reference['recovery_id']))
    else:unittest.main(verbosity=2)
