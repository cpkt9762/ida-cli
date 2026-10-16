"""One fresh idalib process without Nexus or the ida-cli adapter."""
import idapro
import argparse
import json
from pathlib import Path
import shutil
import time
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--engine', choices=('idapro', 'domain', 'getters', 'emptyargs', 'preimport'), default='idapro')
    args = parser.parse_args()
    started = time.monotonic()
    database = None
    if args.engine == 'preimport':
        import ida_domain
    if args.engine == 'domain':
        from ida_domain import Database
        from ida_domain.database import IdaCommandOptions
        database = Database.open(str(args.path), IdaCommandOptions(auto_analysis=False))
    else:
        assert idapro.open_database(str(args.path), False, '' if args.engine=='emptyargs' else None) == 0
    import ida_loader
    import ida_netnode
    import ida_nalt
    import ida_ida
    result = dict(engine=args.engine, path=str(args.path), opened_at=time.monotonic(),
                  started_at=started, probes=[])
    if args.engine == 'getters':
        result['root_before_getters'] = bool(ida_netnode.netnode.exist('Root Node'))
        result['metadata_getters'] = dict(input=ida_nalt.get_input_file_path(),
            size=ida_nalt.retrieve_input_file_size(), md5=str(ida_nalt.retrieve_input_file_md5()),
            sha256=str(ida_nalt.retrieve_input_file_sha256()))

    def sample():
        files = []
        for p in sorted(args.path.parent.iterdir()):
            value = p.lstat()
            files.append(dict(name=p.name, size=value.st_size, mtime_ns=value.st_mtime_ns,
                              inode=value.st_ino, device=value.st_dev))
        return dict(time=time.monotonic(), root=bool(ida_netnode.netnode.exist('Root Node')),
                    path_idb=ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
                    path_id0=ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
                    input=ida_nalt.get_input_file_path(), size=ida_nalt.retrieve_input_file_size(),
                    thread={'current':threading.get_ident(),'main':threading.main_thread().ident},
                    files=files, pack=ida_ida.inf_pack_idb(), compress=ida_ida.inf_compress_idb(),
                    flags={n:ida_loader.is_database_flag(getattr(ida_loader,n))
                           for n in ('DBFL_KILL','DBFL_COMP','DBFL_BAK','DBFL_TEMP')})
    try:
        first = sample()
        result['probes'].append(first)
        if not first['root']:
            # Read-only copies of this trial's live on-disk components. They are
            # not claimed to include unflushed IDA memory buffers.
            capture = args.result.parent/'active-components'
            capture.mkdir()
            for p in args.path.parent.iterdir():
                if p.suffix in ('.id0','.id1','.id2','.nam','.til'):
                    shutil.copyfile(p,capture/p.name)
            for delay in (.05,.2,1):
                time.sleep(max(0,first['time']+delay-time.monotonic()))
                result['probes'].append(sample())
    finally:
        # All inputs are private copies; never save an abnormal session.
        if database is None:
            idapro.close_database(False)
        else:
            database.close(save=False)
        result['closed_at'] = time.monotonic()
        args.result.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'root':first['root'],'engine':args.engine}),flush=True)


if __name__ == '__main__':
    main()
