"""Bound an owned subprocess group and reap its exact child before returning."""
import os
import signal
import subprocess


def run(argv, *, timeout, check=False, **kwargs):
    with subprocess.Popen(argv, start_new_session=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.communicate()
            raise
    result = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result
