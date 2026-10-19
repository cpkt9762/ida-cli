"""Same-process mount cache invalidation over two private HFS+ UUIDs."""
import hashlib,json,os,plistlib,subprocess,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(REPO/'tests/nexus_bridge')]
from test_mount_cache import MountCache
import target_coordination as coordination
base=Path(os.environ['R2_CASE_ROOT'])/'images';base.mkdir(mode=0o700)
mount=base/'mount';mount.mkdir(mode=0o700)
def run(*argv):
 result=subprocess.run(['timeout','180s',*map(str,argv)],capture_output=True,check=True)
 print(json.dumps({'argv':list(map(str,argv)),'exit':result.returncode}),flush=True)
 return result.stdout
for name in ('a','b'):
 run('hdiutil','create','-size','64m','-fs','HFS+','-volname','R6FixCache'+name,base/(name+'.dmg'))
records=[];mounted=False
try:
 for index,name in enumerate(('a','b','a')):
  run('hdiutil','attach','-nobrowse','-owners','on','-mountpoint',mount,base/(name+'.dmg'));mounted=True
  expected=plistlib.loads(run('diskutil','info','-plist',mount))['VolumeUUID']
  fd=os.open(mount,os.O_RDONLY|os.O_DIRECTORY)
  try:key=coordination.capability_key(fd,coordination.native_mount(fd))
  finally:os.close(fd)
  case=mount/('case'+str(index));case.mkdir(mode=0o700)
  one=case/'one.i64';two=case/'two.i64';one.write_bytes(b'private');two.write_bytes(b'private')
  def bind(path):
   with coordination.Target(path,for_open=True) as target,target.locked():return target.directory.read('volume.json')[0]
  counts=MountCache().counts
  data={}
  cold=counts(lambda:data.update(bind(one)))
  warm=counts(lambda:bind(two))
  assert cold=={'subprocesses':4,'probe_directories':1},cold
  assert warm=={'subprocesses':0,'probe_directories':0},warm
  assert data['scope']['volume_sha256']==hashlib.sha256(expected.encode()).hexdigest(),data
  assert data['scope']['boot_retirement_capability']=='UnsupportedBootScope'
  records.append({'image':name,'key':key,'uuid':expected,'scope':data['scope'],'cold':cold,'warm':warm})
  run('hdiutil','detach',mount);mounted=False
 assert records[0]['uuid']!=records[1]['uuid'] and records[0]['uuid']==records[2]['uuid']
 assert len({json.dumps(r['key']) for r in records})==3
 assert not any(mount.iterdir())
finally:
 if mounted:run('hdiutil','detach',mount)
(Path(os.environ['R2_CASE_ROOT'])/'mount-cache-native.json').write_text(json.dumps(records,indent=2)+'\n')
print(json.dumps({'mount_epochs':len(records),'correct_uuid_and_capabilities':True,'all_detached':True}))
