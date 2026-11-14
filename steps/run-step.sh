#!/bin/sh
# Run one of the lab's tools as a step the live console can start and watch.
#
#   run-step.sh NAME COMMAND [ARGS...]
#
# The tool's output is copied to the shared /lab folder, where the console
# reads it. With LAB_STEP=1 the tool waits until the console asks for it;
# otherwise it runs once straight away (./lab.sh and CI), and after that the
# console can run it again.
#
# The console asks by writing a run number to /lab/go/NAME. It has no access
# to Docker and holds no secret: that file is all it can change here.

name=$1; shift
lab=${LAB_DIR:-/lab}
go=$lab/go/$name
out=$lab/out/$name.log
events=$lab/events/$name.jsonl
status=$lab/out/$name.exit

# Run on its own, without the lab's shared folder: just run the tool.
if [ ! -d "$lab/go" ] || ! ( : >> "$out" ) 2>/dev/null; then
    exec "$@"
fi

trap 'exit 0' TERM INT

event() {
    printf '{"ts":%s,"stage":"%s","kind":"%s","run":%s%s}\n' \
        "$(date +%s.%N)" "$name" "$1" "$run" "$2" >> "$events"
}

requested() {
    n=$(cat "$go" 2>/dev/null)
    case $n in ''|*[!0-9]*) n=0 ;; esac
    echo "$n"
}

finished=0
run=0
[ "$LAB_STEP" = "1" ] || run=1

while :; do
    while [ "$run" -le "$finished" ]; do
        run=$(requested)
        [ "$run" -gt "$finished" ] || sleep 0.3
    done
    event start
    { "$@" 2>&1; echo $? > "$status"; } | tee -a "$out"
    code=$(cat "$status" 2>/dev/null)
    case $code in ''|*[!0-9]*) code=1 ;; esac
    event end ",\"exit\":$code"
    finished=$run
done
