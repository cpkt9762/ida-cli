"""Test-only process exits around the unchanged installed file-job authority.

Only the feature-gated Rust launcher and native input fixture import this file.
No proof, SDK outcome, component byte or production decision is substituted.
"""
import json
import os
from pathlib import Path
import runpy
import sys


def install(role):
    fault=os.environ.get('R4_FILE_JOB_FAULT')
    if not fault:
        return
    root=Path(os.environ['R3A_CASE_ROOT'])
    marker=root/'file-fault-fired.json'

    def fire(stage, binding):
        selected=fault==role+'_'+stage or (fault=='both_exit' and (role,stage) in
            (('source','sent'),('receiver','received')))
        if not selected or (root/('file-fault-fired-'+role+'.json')).exists():
            return
        value={'role':role,'stage':stage,'pid':os.getpid(),'binding':binding}
        with (root/('file-fault-fired-'+role+'.json')).open('x') as output:
            json.dump(value,output)
            output.flush()
            os.fsync(output.fileno())
        try:
            with marker.open('x') as output:
                json.dump(value,output)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:pass
        os._exit(97)

    import recovery_transfer
    original=recovery_transfer.boundary
    def transfer(stage, binding):
        if fault=='source_bad_epoch' and role=='source' and stage=='before_send' and not marker.exists():
            binding['epoch']+=1
            marker.write_text(json.dumps({'role':role,'stage':stage,'binding':binding}))
        fire(stage,binding)
        return original(stage,binding)
    recovery_transfer.boundary=transfer
    if role=='source' and fault=='source_duplicate':
        original_send=recovery_transfer.FrozenOffer.send
        def send(offer,channel):
            class Channel:
                def sendmsg(self,parts,ancillary):
                    length=channel.sendmsg(parts,ancillary)
                    duplicate=channel.sendmsg(parts,ancillary)
                    if length!=duplicate:raise AssertionError('duplicate transfer length differs')
                    marker.write_text(json.dumps({'role':role,'stage':'duplicate','binding':offer.binding}))
                    return length
            return original_send(offer,Channel())
        recovery_transfer.FrozenOffer.send=send
    if role=='receiver':
        fire('start',{'argv':sys.argv[1:]})
        import recovery_files
        import recovery_transaction
        original_file=recovery_files.boundary
        def files(action,stage,detail):
            if action=='phase' and stage=='staging':fire('first_intent',detail)
            if action=='rename' and stage=='after':fire('after_rename',detail)
            return original_file(action,stage,detail)
        recovery_files.boundary=files
        recovery_transaction.boundary=files
        import recovery_job
        original_execute=recovery_job.execute
        def execute(channel,path,recovery_id):
            class Channel:
                def send(self, raw):
                    value=json.loads(raw)
                    if 'actor' in value:fire('ready',value)
                    if fault=='receiver_drop_ack' and value.get('accepted') is True:
                        # This affects delivery only, after durable Accepted.
                        (root/'file-ack-dropped').touch()
                        return len(raw)
                    return channel.send(raw)
                def __getattr__(self,name):return getattr(channel,name)
            return original_execute(Channel(),path,recovery_id)
        recovery_job.execute=execute


if __name__=='__main__':
    bootstrap=sys.argv.pop(1)
    sys.argv[0]=bootstrap
    entry=runpy.run_path(bootstrap,run_name='verified_file_fault')['load_entry']()
    install('receiver')
    entry.main()
