#!/bin/sh
# crash_exit_status.sh — regression test for issue #2.
#
# In offline mode (-t <pcap>) a crash signal must make the probe exit with
# 128 + signum instead of 0, and a clean shutdown (end of pcap, SIGINT,
# SIGTERM) must still exit 0.
#
# Run from the repository root after `make ... compile`, e.g.:
#   make test-crash
# or directly:
#   sh test/crash_exit_status.sh
#
# Environment overrides:
#   PROBE   probe binary            (default: <repo>/probe)
#   CONF    probe configuration     (default: <repo>/mmt-probe.conf)
#   PCAP    small check pcap        (default: <repo>/test/UA-Exp01.pcap)
#   REPEAT  body repeats of the long pcap (default: 600, ~1.1M packets)

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)

PROBE=${PROBE:-"$ROOT/probe"}
CONF=${CONF:-"$ROOT/mmt-probe.conf"}
PCAP=${PCAP:-"$ROOT/test/UA-Exp01.pcap"}
REPEAT=${REPEAT:-600}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/probe-exit-status.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

fail=0
say()  { printf '%s\n' "$*"; }
pass() { say "PASS: $*"; }
bad()  { say "FAIL: $*"; fail=1; }

for f in "$PROBE" "$CONF" "$PCAP"; do
	[ -f "$f" ] || { say "missing: $f"; exit 2; }
done
[ -x "$PROBE" ] || { say "not executable: $PROBE"; exit 2; }

mkdir -p "$WORK/reports"

# A pcap long enough that the probe is still inside its capture loop when
# the test signals it: the global header of PCAP followed by its packet
# records repeated REPEAT times.
LONG="$WORK/long.pcap"
head -c 24 "$PCAP" > "$LONG"
tail -c +25 "$PCAP" > "$WORK/body"
i=0
while [ "$i" -lt "$REPEAT" ]; do
	cat "$WORK/body" >> "$LONG"
	i=$((i + 1))
done
rm -f "$WORK/body"
say "long pcap: $(wc -c < "$LONG") bytes"

# start_probe <pcap> <log>: start the probe in background; its pid lands in
# $PROBE_PID. Must run in the current shell: a command substitution would
# orphan the probe and `wait` could not reap it.
PROBE_PID=
start_probe() {
	"$PROBE" -c "$CONF" -t "$1" \
		-X "file-output.output-dir=$WORK/reports/" \
		>"$2" 2>&1 &
	PROBE_PID=$!
}

# wait_marker <log>: wait until the probe's signal handlers are installed
# (the "is running on pid" line comes after signal() registration).
wait_marker() {
	i=0
	while [ "$i" -lt 2000 ]; do
		grep -q "is running on pid" "$1" 2>/dev/null && return 0
		i=$((i + 1))
		sleep 0.01
	done
	return 1
}

check() { # <name> <expected> <actual>
	if [ "$2" = "$3" ]; then
		pass "$1: exit status $3"
	else
		bad "$1: expected exit status $2, got $3"
	fi
}

# 1. end of pcap is a clean shutdown: status 0.
start_probe "$PCAP" "$WORK/eof.log"
pid=$PROBE_PID
wait "$pid"
check "end-of-pcap" 0 $?
grep -q "reached to the end of pcap file" "$WORK/eof.log" \
	&& pass "end-of-pcap: eof log marker" \
	|| bad "end-of-pcap: no eof log marker"

# 2. signals on the long pcap. INT and TERM are clean shutdowns (0);
# crash signals must be 128 + signum.
for spec in "INT 0" "TERM 0" "SEGV 139" "ABRT 134" "BUS 135" "FPE 136" "ILL 132"; do
	set -- $spec
	sig=$1
	want=$2
	logf="$WORK/sig-$sig.log"

	start_probe "$LONG" "$logf"
	pid=$PROBE_PID
	if ! wait_marker "$logf"; then
		bad "SIG$sig: no start-up marker in log"
		kill -9 "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		continue
	fi
	if ! kill -"$sig" "$pid" 2>/dev/null; then
		bad "SIG$sig: probe exited before the signal was sent"
		wait "$pid" 2>/dev/null
		continue
	fi
	# wait for the probe, with a watchdog that kills it after 10 s
	( sleep 10; kill -9 "$pid" 2>/dev/null ) &
	wd=$!
	wait "$pid"
	rc=$?
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ "$rc" = 137 ]; then
		bad "SIG$sig: probe did not exit within 10 s (watchdog killed it)"
		continue
	fi
	check "SIG$sig" "$want" "$rc"
done

say "---"
if [ "$fail" -eq 0 ]; then
	say "all checks passed"
else
	say "some checks failed"
fi
exit "$fail"
