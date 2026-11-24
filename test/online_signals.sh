#!/bin/sh
# online_signals.sh — regression tests for issues #7 and #10.
#
# In online mode the probe runs a monitor (supervisor) process that forks a
# processing child. Issue #7: the monitor ignored SIGINT/SIGTERM, so a signal
# sent to it only (docker stop, systemctl stop) degraded to SIGKILL after the
# grace period and reports were not flushed. Issue #10: the processing child
# always exited 0, so a start-up failure looked like a clean stop.
#
# This checks:
#  - the monitor forwards SIGTERM and SIGINT to the processing child, waits
#    for it and exits with its status: 0 on a clean shutdown, with reports
#    flushed;
#  - a start-up error (an input that cannot be used) makes the child exit
#    with the do-not-restart status (EXIT_STATUS_NO_RESTART = 3, defined in
#    src/lib/limit.h): the monitor does not restart it and exits non-zero;
#  - a SIGSEGV still auto-restarts the child;
#  - "docker stop" on a probe container exits 0 quickly - only when
#    DOCKER_IMAGE names an image holding this probe and a docker daemon is
#    reachable.
#
# Run from the repository root after `make ... compile`, e.g.:
#   make test-online-signals
# or directly (the probe must be able to capture on IFACE, i.e. CAP_NET_RAW):
#   sh test/online_signals.sh
#
# Environment overrides:
#   PROBE        probe binary            (default: <repo>/probe)
#   CONF         probe configuration     (default: <repo>/mmt-probe.conf)
#   ROOT         repository root mounted by the docker-stop check's
#                sibling container       (default: <repo>)
#   IFACE        capture interface       (default: lo)
#   REPEAT_TERM  repeats of the monitor-SIGTERM check (default: 1)
#   DOCKER_IMAGE image for the docker-stop check (default: skip)
#   CC           compiler for wait_fate  (default: cc)

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$SELF_DIR/.." && pwd)}

PROBE=${PROBE:-"$ROOT/probe"}
CONF=${CONF:-"$ROOT/mmt-probe.conf"}
IFACE=${IFACE:-lo}
REPEAT_TERM=${REPEAT_TERM:-1}
DOCKER_IMAGE=${DOCKER_IMAGE:-}
CC=${CC:-cc}

# EXIT_STATUS_NO_RESTART (src/lib/limit.h) and its raw waitpid encoding,
# which is what the monitor logs as the child's "return code"
DNR_STATUS=3
DNR_WAIT=$(( DNR_STATUS * 256 ))
RESTART_WAIT=256   # EXIT_TOBE_RESTARTED -> _exit(EXIT_FAILURE)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/probe-online-signals.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

fail=0
say()  { printf '%s\n' "$*"; }
pass() { say "PASS: $*"; }
bad()  { say "FAIL: $*"; fail=1; }

for f in "$PROBE" "$CONF"; do
	[ -f "$f" ] || { say "missing: $f"; exit 2; }
done
[ -x "$PROBE" ] || { say "not executable: $PROBE"; exit 2; }

command -v "$CC" >/dev/null 2>&1 || CC=gcc
"$CC" -Wall -O1 -o "$WORK/wait_fate" "$SELF_DIR/wait_fate.c" \
	|| { say "cannot build wait_fate with $CC"; exit 2; }

mkdir -p "$WORK/reports"

# start_probe <log>: start wait_fate (which forks and execs the probe in
# online mode) in background; the wrapper's pid lands in $WRAPPER_PID and
# the supervisor's own pid in $WORK/pid. The short periods make a report
# file appear after about 3 s.
start_probe() {
	: > "$WORK/pid"
	: > "$WORK/fate"
	rm -f "$WORK"/reports/*
	"$WORK/wait_fate" "$WORK/pid" "$WORK/fate" \
		"$PROBE" -c "$CONF" -i "$IFACE" \
		-X "file-output.output-dir=$WORK/reports/" \
		-X "stats-period=2" \
		-X "output.cache-period=2" \
		>"$1" 2>&1 &
	WRAPPER_PID=$!
}

# wait_grep <pattern> <file> <tenths>: wait until <file> contains <pattern>
wait_grep() {
	i=0
	while [ "$i" -lt "$3" ]; do
		grep -q "$1" "$2" 2>/dev/null && return 0
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

# wait_pidfile <tenths>: wait until $WORK/pid holds the supervisor's pid -
# wait_fate writes it after fork() while the child is already running, so
# it can still be empty when the start-up marker first shows in the log
wait_pidfile() {
	i=0
	while [ "$i" -lt "$1" ]; do
		[ -s "$WORK/pid" ] && return 0
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

# wait_file_count <dir> <tenths>: wait until <dir> holds a regular file
wait_file_count() {
	i=0
	while [ "$i" -lt "$2" ]; do
		[ -n "$(find "$1" -type f -print -quit 2>/dev/null)" ] && return 0
		i=$((i + 1))
		sleep 0.1
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

fate() { cat "$WORK/fate" 2>/dev/null; }

# the processing child's pid: the pid in the last "Create a new sub-process"
# line of the supervisor's log
child_pid() {
	sed -n 's/.*Create a new sub-process \([0-9][0-9]*\) for main processing/\1/p' \
		"$1" | tail -n 1
}

# no_orphans <pid>...: every pid must be fully gone (no zombie, no stray)
no_orphans() {
	for p in "$@"; do
		[ -n "$p" ] || continue
		[ -e "/proc/$p" ] 2>/dev/null && { bad "orphan process left: $p"; return 1; }
	done
	return 0
}

# wait_wrapper <name>: wait for $WRAPPER_PID with a watchdog like the crash
# test; returns the wrapper's exit status in $RC, -1 on watchdog kill
wait_wrapper() {
	(
		sleep_pid=
		trap '[ -n "$sleep_pid" ] && kill "$sleep_pid" 2>/dev/null; exit 1' TERM
		sleep 15 & sleep_pid=$!
		wait "$sleep_pid" 2>/dev/null
		kill -9 "$WRAPPER_PID" 2>/dev/null
	) &
	wd=$!
	wait "$WRAPPER_PID"
	RC=$?
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ "$RC" = 137 ]; then
		bad "$1: probe did not exit within 15 s (watchdog killed it)"
		RC=-1
	fi
}

# check_reports <name>: the reports written before the signal must be
# flushed. A *.sem file is the probe's zero-byte "file complete" marker and
# sample files are created eagerly, so only non-empty files are checked for
# a terminating newline; at least one file must hold flushed data.
check_reports() {
	nb=$(find "$WORK/reports" -type f ! -name '*.sem' 2>/dev/null | wc -l)
	if [ "$nb" -eq 0 ]; then
		bad "$1: no report file was written"
		return
	fi
	nb_data=0
	nb_bad=0
	for f in "$WORK"/reports/*; do
		case "$f" in *.sem) continue;; esac
		[ -s "$f" ] || continue
		nb_data=$((nb_data + 1))
		[ -z "$(tail -c 1 "$f")" ] || nb_bad=$((nb_bad + 1))
	done
	if [ "$nb_data" -eq 0 ]; then
		bad "$1: $nb report file(s) written but all empty (flush lost?)"
	elif [ "$nb_bad" -eq 0 ]; then
		pass "$1: $nb_data report file(s) flushed and complete"
	else
		bad "$1: $nb_bad report file(s) truncated"
	fi
}

# run_shutdown <sig> <name>: one online run ended by <sig> sent to the
# supervisor. Asserts: exit within a few seconds with status 0, the child
# exited 0 ("return code: 0"), the shutdown path ran and reports flushed.
run_shutdown() {
	sig=$1
	name=$2
	logf="$WORK/sig-$sig-$name.log"
	sup_pid=
	kid=

	start_probe "$logf"
	if ! wait_grep "is running on pid" "$logf" 200; then
		bad "$name: no start-up marker in log"
		grep -q "Couldn't open device\|Cannot activate" "$logf" \
			&& say "note: cannot capture on $IFACE (missing CAP_NET_RAW?)"
		kill -9 "$WRAPPER_PID" 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
		return 1
	fi
	wait_pidfile 50 || { bad "$name: no supervisor pid recorded"; return 1; }
	sup_pid=$(cat "$WORK/pid" 2>/dev/null)
	kid=$(child_pid "$logf")
	#let the probe produce at least one report file before the signal
	wait_file_count "$WORK/reports" 100 || true

	t0=$(date +%s)
	if ! kill -"$sig" "$sup_pid" 2>/dev/null; then
		bad "$name: supervisor exited before SIG$sig was sent"
		tail -n 20 "$logf" | sed 's/^/    log: /'
		wait "$WRAPPER_PID" 2>/dev/null
		return 1
	fi
	wait_wrapper "$name"
	t1=$(date +%s)
	[ "$RC" = -1 ] && return 1
	check "$name status" 0 "$RC"
	check "$name fate" "exit 0" "$(fate)"
	elapsed=$((t1 - t0))
	[ "$elapsed" -le 9 ] \
		&& pass "$name: exited in ${elapsed}s" \
		|| bad "$name: took ${elapsed}s to exit"
	grep -q "Received SIG$sig" "$logf" \
		&& pass "$name: child handled SIG$sig" \
		|| bad "$name: no SIG$sig marker in log"
	grep -q "return code: 0" "$logf" \
		&& pass "$name: child exited 0" \
		|| bad "$name: no clean-exit marker in log"
	check_reports "$name"
	no_orphans "$sup_pid" "$kid"
	return 0
}

say "online supervisor signal checks (probe: $PROBE, iface: $IFACE)"

# 1. SIGTERM to the supervisor: clean shutdown, repeated
# (rep is used, not i: the helpers above share the caller's i)
rep=0
while [ "$rep" -lt "$REPEAT_TERM" ]; do
	run_shutdown TERM "sigterm-$rep"
	rep=$((rep + 1))
done

# 2. SIGINT to the supervisor: same expectations
run_shutdown INT "sigint"

# 3. a start-up error: the input cannot be used, the child must report the
# do-not-restart status and the monitor must not restart it
logf="$WORK/bad-config.log"
: > "$WORK/pid"; : > "$WORK/fate"
"$WORK/wait_fate" "$WORK/pid" "$WORK/fate" \
	"$PROBE" -c "$CONF" -i "i710-no-such-iface" \
	>"$logf" 2>&1 &
WRAPPER_PID=$!
wait_wrapper "bad-config"
if [ "$RC" != -1 ]; then
	check "bad-config status" "$DNR_STATUS" "$RC"
	check "bad-config fate" "exit $DNR_STATUS" "$(fate)"
	grep -q "return code: $DNR_WAIT" "$logf" \
		&& pass "bad-config: monitor saw do-not-restart status" \
		|| bad "bad-config: no do-not-restart marker in log"
	nb=$(grep -c "Create a new sub-process" "$logf")
	check "bad-config restarts" 1 "$nb"
fi

# 4. a crash still auto-restarts the processing child
logf="$WORK/segv.log"
start_probe "$logf"
if ! wait_grep "is running on pid" "$logf" 200; then
	bad "segv-restart: no start-up marker in log"
	kill -9 "$WRAPPER_PID" 2>/dev/null
	wait "$WRAPPER_PID" 2>/dev/null
else
	if ! wait_pidfile 50; then
		bad "segv-restart: no supervisor pid recorded"
		kill -9 "$WRAPPER_PID" 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
	else
		sup_pid=$(cat "$WORK/pid" 2>/dev/null)
		kid=$(child_pid "$logf")
		if ! kill -SEGV "$kid" 2>/dev/null; then
			bad "segv-restart: processing child exited before the signal"
		else
			#wait for the supervisor to create a replacement child
			i=0
			while [ "$i" -lt 100 ]; do
				[ "$(grep -c "Create a new sub-process" "$logf")" -ge 2 ] && break
				i=$((i + 1)); sleep 0.1
			done
			if [ "$(grep -c "Create a new sub-process" "$logf")" -ge 2 ]; then
				pass "segv-restart: child re-created"
				new_kid=$(child_pid "$logf")
				[ "$new_kid" != "$kid" ] \
					&& pass "segv-restart: new pid $new_kid" \
					|| bad "segv-restart: same pid $new_kid"
				grep -q "return code: $RESTART_WAIT" "$logf" \
					&& pass "segv-restart: restart status seen" \
					|| bad "segv-restart: no restart status in log"
			else
				bad "segv-restart: child was not re-created"
			fi
			#the restarted child must be fully up (its handlers installed)
			# before the second TERM: wait for its "is running on pid" line
			i=0
			while [ "$i" -lt 200 ]; do
				[ "$(grep -c "is running on pid" "$logf")" -ge 2 ] && break
				i=$((i + 1)); sleep 0.1
			done
			#the probe must still stop cleanly afterwards
			kill -TERM "$sup_pid" 2>/dev/null
		fi
	fi
	wait_wrapper "segv-restart"
	[ "$RC" = -1 ] || {
		check "segv-restart status" 0 "$RC"
		check "segv-restart fate" "exit 0" "$(fate)"
		no_orphans "$sup_pid" "$kid" "${new_kid:-}"
	}
fi

# 5. docker stop on a containerized probe: exits 0, well under the 10 s
# grace period - only when an image and a daemon are provided. The
# container runs with --rm; a docker wait subscribed before the stop still
# reports the exit code once the container is gone.
if [ -n "$DOCKER_IMAGE" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	name="i710-stop-$$"
	if docker run -d --rm --name "$name" --cap-add NET_RAW \
		-v "$ROOT:$ROOT:ro" --entrypoint "$ROOT/probe" \
		"$DOCKER_IMAGE" -c "$ROOT/mmt-probe.conf" -i "$IFACE" \
		-X "file-output.output-dir=/tmp/i710-reports" >/dev/null 2>&1; then
		#subscribe to the container's exit before stopping it
		docker wait "$name" > "$WORK/docker-stop-rc" 2>/dev/null &
		waiter=$!
		sleep 0.3
		#wait for the processing child to be up (docker logs)
		i=0
		while [ "$i" -lt 200 ]; do
			docker logs "$name" 2>&1 | grep -q "is running on pid" && break
			i=$((i + 1)); sleep 0.1
		done
		t0=$(date +%s)
		docker stop "$name" >/dev/null 2>&1
		t1=$(date +%s)
		rc=$(cat "$WORK/docker-stop-rc" 2>/dev/null)
		wait "$waiter" 2>/dev/null
		check "docker-stop status" 0 "$rc"
		elapsed=$((t1 - t0))
		[ "$elapsed" -lt 9 ] \
			&& pass "docker-stop: exited in ${elapsed}s" \
			|| bad "docker-stop: took ${elapsed}s (SIGKILL grace is 10 s)"
	else
		bad "docker-stop: cannot start the container"
	fi
	docker kill "$name" >/dev/null 2>&1 || true
else
	say "SKIP: docker-stop check (set DOCKER_IMAGE with docker reachable to run it)"
fi

say "---"
if [ "$fail" -eq 0 ]; then
	say "all checks passed"
else
	say "some checks failed"
fi
exit "$fail"
