"""Internal bridge wire fixture for production Rust open_owned fault injection."""
import json,os,socket,sys,threading,time
from pathlib import Path
root=Path(os.environ['IDA_CLI_HOME'])
fault=os.environ.get('N4_F2_OPEN_FAULT','')
(root/'bridge-process.json').write_text(json.dumps({'pid':os.getpid()}))
caps={'runtime':{'ida':[9,5,0],'python':[3,11,0],'nexus':[0,13,4],'domain':[0,5,1]},'methods':{}}
print(json.dumps({'ready':True,'capabilities':caps}),flush=True)
lock=threading.Lock();first=[True]
def send(stream,obj):
    stream.sendall((json.dumps(obj)+'\n').encode())
def serve(path):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.connect(path)
        frames={}; inject_grant={}
        for raw in stream.makefile('rb'):
            frame=json.loads(raw)
            if 'local_status' in frame:
                send(stream,{'event':'local_status','id':frame['local_status']});continue
            if 'grant' in frame:
                saved=frames.pop(frame['sequence'])
                if not frame['grant']:continue
                attempt=saved['attempt'];command=saved['payload'];kind=command['command']
                if kind=='open':
                    if inject_grant.pop(attempt['sequence'],False):
                        (root/'before-grant').touch()
                        while not (root/'grant-release').exists():time.sleep(.005)
                    identity=command['identity']
                    lease={'client_id':identity['client_id'],'lease_id':identity['operation_id'],'instance_id':'fixture-owner','generation':1,'owner':'managed'}
                    send(stream,{'event':'opened','attempt':attempt,'lease':lease,'capabilities':caps,'idb_path':command['path'],'pid':os.getpid()})
                elif kind=='release':
                    if fault in ('release-proof','release-unconfirmed'):
                        send(stream,{'event':'uncertain','attempt':attempt,'error':{'code':'cancel_pending','message':'injected lost release ACK'}})
                        (root/'release-uncertain').touch()
                        if fault=='release-proof':
                            end=time.monotonic()+5
                            while not (root/'release-proof').exists():
                                assert time.monotonic()<end,'missing release proof barrier'
                                time.sleep(.005)
                        else:
                            send(stream,{'event':'release_unconfirmed','attempt':attempt})
                            continue
                    send(stream,{'event':'released','attempt':attempt})
                else:raise AssertionError(kind)
                continue
            attempt=frame['attempt'];kind=frame['payload']['command']
            with lock:
                inject=kind=='open' and first[0]
                if inject:first[0]=False
            if inject and fault in ('not-sent','remote-error'):
                send(stream,{'event':'not_sent' if fault=='not-sent' else 'remote_error','attempt':attempt,'error':{'code':'busy','message':'injected bridge backpressure'}})
                continue
            if inject and fault in ('cancel','deadline'):
                (root/'before-grant').touch()
                while not (root/'grant-release').exists():time.sleep(.005)
            inject_grant[attempt['sequence']]=inject and fault=='deadline-fallback'
            frames[attempt['sequence']]=frame
            send(stream,{'event':'dispatch_ready','frame':frame})
threads=[threading.Thread(target=serve,args=(path,),daemon=True) for path in sys.argv[1:3]]
for thread in threads:thread.start()
sys.stdin.buffer.read()
