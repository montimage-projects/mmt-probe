#!/bin/sh
# inner_container.sh - runs inside the NET_RAW_IMAGE container for the
# online double-signal leg of test/online_signals.sh (issue #45). The
# image bakes the probe with cap_net_raw so the unprivileged container
# user can capture on the container's loopback.
#
# The scenario mirrors systemd's KillMode=control-group stop: the probe
# tree runs in its own process group and a group-wide SIGINT reaches the
# processing child both directly and through the monitor's forward while
# the drain still runs - the repeat must be a no-op so the drain
# finishes.
#
# Input (environment):
#   CONF   probe configuration file inside the container
#          (default: /work/probe-inner.conf, written by the outer leg:
#          online mode on IFACE, sampled file output into /work/reports)
#   PROBE  probe binary in the image   (default: /opt/mmt/probe/probe)
# Output (in /work, the writable mount the outer leg inspects):
#   log       the probe tree's combined log
#   reports/  the sampled file output
#   verdict   one PASS:/FAIL: line per assertion, ended by 'done'

set -u

PROBE=${PROBE:-/opt/mmt/probe/probe}
CONF=${CONF:-/work/probe-inner.conf}
WORK=/work
REPORTS=$WORK/reports

mkdir -p "$REPORTS"
: > "$WORK/log"
: > "$WORK/verdict"

verdict() {
	echo "$1" >> "$WORK/verdict"
}

#loopback traffic so the drain has live sessions to flush
udp_gen 127.0.0.1 40000 &
gen_pid=$!

#the probe tree in its own process group - setsid gives the group the
# supervisor's pid - so a group kill reaches monitor AND children
setsid "$PROBE" -c "$CONF" \
	> "$WORK/log" 2>&1 &
sup=$!

#wait for the processing child to be up
i=0
while [ "$i" -lt 300 ] && ! grep -q "is running on pid" "$WORK/log"; do
	kill -0 "$sup" 2>/dev/null || break
	i=$((i + 1)); sleep 0.1
done
kid=$(sed -n 's/.*Create a new sub-process \([0-9]*\) for main processing/\1/p' "$WORK/log" | tail -1)

if ! kill -0 "$sup" 2>/dev/null || [ -z "$kid" ]; then
	verdict "FAIL: processing child did not start (log follows)"
	sed 's/^/log: /' "$WORK/log" | tail -20 >> "$WORK/verdict" || true
	echo done >> "$WORK/verdict"
	kill "$gen_pid" 2>/dev/null || true
	exit 0
fi

#let traffic accumulate live sessions, then the double signal: the group
# kill hits the child AND the monitor, whose forward is the repeat; the
# delayed direct kill covers a longer drain window
sleep 1
kill -INT -"$sup" 2>/dev/null || true
sleep 0.05
kill -INT "$kid" 2>/dev/null || true

i=0
while [ "$i" -lt 300 ] && kill -0 "$sup" 2>/dev/null; do
	i=$((i + 1)); sleep 0.1
done
wait "$sup" 2>/dev/null
rc=$?
kill "$gen_pid" 2>/dev/null || true
kill -9 -"$sup" 2>/dev/null || true

if [ "$rc" -eq 0 ]; then
	verdict "PASS: supervisor exit 0"
else
	verdict "FAIL: supervisor exit $rc"
fi

#the final statistics only print while the drain runs
if grep -q "processed" "$WORK/log"; then
	verdict "PASS: final statistics logged"
else
	verdict "FAIL: no final statistics - drain skipped"
fi

#on the unfixed code the repeat reports and exits immediately
if grep -q "while processing other one" "$WORK/log"; then
	verdict "FAIL: immediate exit on a repeated signal"
else
	verdict "PASS: no immediate exit on a repeat"
fi

if find "$REPORTS" -name '*.sem' -type f | grep -q .; then
	verdict "PASS: .sem marker written"
else
	verdict "FAIL: no .sem marker - output not closed"
fi

if ls "$REPORTS"/* >/dev/null 2>&1; then
	verdict "PASS: reports written"
else
	verdict "FAIL: no reports written"
fi

echo done >> "$WORK/verdict"
exit 0
