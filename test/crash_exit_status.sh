#!/bin/sh
# crash_exit_status.sh — regression test for issue #2.
#
# In offline mode (-t <pcap>) a crash signal must kill the probe with that
# signal: a consumer then sees a signal death (WIFSIGNALED from waitpid;
# a shell reports it as 128 + signum). A clean shutdown (end of pcap,
# SIGINT, SIGTERM) must still exit 0.
#
# POSIX wait reports 128+signum both for a signal death and for
# _exit(128+signum), so the probe is spawned through test/wait_fate
# (compiled below): it waitpid()s the probe and records whether it exited
# or was killed by a signal.
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
#   CC      compiler for wait_fate  (default: cc)

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)

PROBE=${PROBE:-"$ROOT/probe"}
CONF=${CONF:-"$ROOT/mmt-probe.conf"}
PCAP=${PCAP:-"$ROOT/test/UA-Exp01.pcap"}
REPEAT=${REPEAT:-600}
CC=${CC:-cc}

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

command -v "$CC" >/dev/null 2>&1 || CC=gcc
"$CC" -Wall -O1 -o "$WORK/wait_fate" "$SELF_DIR/wait_fate.c" \
	|| { say "cannot build wait_fate with $CC"; exit 2; }

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

# start_probe <pcap> <log>: start wait_fate (which forks and execs the
# probe) in background; the wrapper's pid lands in $WRAPPER_PID, the probe's
# own pid in $WORK/pid.
WRAPPER_PID=
start_probe() {
	: > "$WORK/pid"
	: > "$WORK/fate"
	"$WORK/wait_fate" "$WORK/pid" "$WORK/fate" \
		"$PROBE" -c "$CONF" -t "$1" \
		-X "file-output.output-dir=$WORK/reports/" \
		>"$2" 2>&1 &
	WRAPPER_PID=$!
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
		pass "$1: $3"
	else
		bad "$1: expected $2, got $3"
	fi
}

# fate: the fate file written by wait_fate says how the probe really ended
# ("signal N" = WIFSIGNALED, "exit N" = WIFEXITED).
fate() { cat "$WORK/fate" 2>/dev/null; }

# 1. end of pcap is a clean shutdown: status 0.
start_probe "$PCAP" "$WORK/eof.log"
wait "$WRAPPER_PID"
check "end-of-pcap" 0 $?
check "end-of-pcap fate" "exit 0" "$(fate)"
grep -q "reached to the end of pcap file" "$WORK/eof.log" \
	&& pass "end-of-pcap: eof log marker" \
	|| bad "end-of-pcap: no eof log marker"

# 2. signals on the long pcap. INT and TERM are clean shutdowns (exit 0);
# crash signals must kill the probe with that signal (fate "signal N",
# shell status 128+N).
for spec in "INT 0" "TERM 0" "SEGV 139" "ABRT 134" "BUS 135" "FPE 136" "ILL 132"; do
	set -- $spec
	sig=$1
	want_rc=$2
	# expected fate: INT/TERM exit cleanly, crash signals die by the signal
	case "$sig" in
	INT|TERM) want_fate="exit 0" ;;
	SEGV) want_fate="signal 11" ;;
	ABRT) want_fate="signal 6" ;;
	BUS)  want_fate="signal 7" ;;
	FPE)  want_fate="signal 8" ;;
	ILL)  want_fate="signal 4" ;;
	esac
	logf="$WORK/sig-$sig.log"

	start_probe "$LONG" "$logf"
	if ! wait_marker "$logf"; then
		bad "SIG$sig: no start-up marker in log"
		kill -9 "$WRAPPER_PID" 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
		continue
	fi
	# the wrapper writes the probe's pid right after fork, but wait for it
	# explicitly so a fast marker cannot race ahead of the write
	i=0
	while [ "$i" -lt 200 ] && [ ! -s "$WORK/pid" ]; do
		i=$((i + 1)); sleep 0.01
	done
	probe_pid=$(cat "$WORK/pid")
	if ! kill -"$sig" "$probe_pid" 2>/dev/null; then
		bad "SIG$sig: probe exited before the signal was sent"
		wait "$WRAPPER_PID" 2>/dev/null
		continue
	fi
	# wait for the probe, with a watchdog that kills it after 10 s
	( sleep 10; kill -9 "$probe_pid" 2>/dev/null; kill -9 "$WRAPPER_PID" 2>/dev/null ) &
	wd=$!
	wait "$WRAPPER_PID"
	rc=$?
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ "$rc" = 137 ]; then
		bad "SIG$sig: probe did not exit within 10 s (watchdog killed it)"
		continue
	fi
	check "SIG$sig status" "$want_rc" "$rc"
	check "SIG$sig fate" "$want_fate" "$(fate)"
	case "$sig" in
	INT|TERM) ;;
	*) grep -q "crash signal received: ${want_fate#signal }" "$logf" \
		&& pass "SIG$sig: crash report in log" \
		|| bad "SIG$sig: no crash report in log" ;;
	esac
done

say "---"
if [ "$fail" -eq 0 ]; then
	say "all checks passed"
else
	say "some checks failed"
fi
exit "$fail"
