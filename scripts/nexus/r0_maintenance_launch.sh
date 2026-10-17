#!/bin/sh
# Prototype official launcher: environment is cleared BEFORE Python/site initialization.
set -eu
python=$1
installation=$2
mode=$3
shift 3
case "$python:$installation" in /*:/*) ;; *) exit 64 ;; esac
case "$mode" in
  ordinary) exec env -i HOME="$installation/home" PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 "$python" "$installation/r0_bootstrap.py" "$@" ;;
  isolated) exec env -i HOME="$installation/home" PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 "$python" -I "$installation/r0_bootstrap.py" "$@" ;;
  safe) exec env -i HOME="$installation/home" PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 "$python" -P "$installation/r0_bootstrap.py" "$@" ;;
  envsafe) exec env -i HOME="$installation/home" PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 "$python" "$installation/r0_bootstrap.py" "$@" ;;
  *) exit 64 ;;
esac
