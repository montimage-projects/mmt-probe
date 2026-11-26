#!/bin/sh
# online_signals.sh — regression tests for issues #7, #10 and #45.
#
# In online mode the probe runs a monitor (supervisor) process that forks a
# processing child. Issue #7: the monitor ignored SIGINT/SIGTERM, so a signal
# sent to it only (docker stop, systemctl stop) degraded to SIGKILL after the
# grace period and reports were not flushed. Issue #10: the processing child
# always exited 0, so a start-up failure looked like a clean stop.
# Issue #45: a second identical SIGINT/SIGTERM while the child was shutting
# down made it _exit(0) before the drain - the security drain
# (mmt_sec_unregister), the output fclose/.sem and the stdio flush were
# skipped - and a refused start-up configuration exited 1 although the
# shipped mmt-probe.service treats only exit status 3
# (EXIT_STATUS_NO_RESTART in src/lib/limit.h) as a definitive stop.
#
# This checks:
#  - the monitor forwards SIGTERM and SIGINT to the processing child, waits
#    for it and exits with its status: 0 on a clean shutdown, with reports
#    flushed;
#  - a start-up error (an input that cannot be used) makes the child exit
#    with the do-not-restart status (EXIT_STATUS_NO_RESTART = 3, defined in
#    src/lib/limit.h): the monitor does not restart it and exits non-zero;
#  - a SIGSEGV still auto-restarts the child;
#  - on a build with DYNAMIC_CONFIG_MODULE, a group-wide SIGINT - the
#    systemd KillMode=control-group shape - plus a forwarded SIGTERM stops
#    the monitor and both children with no hang, no orphan and exit 0;
#  - a repeated termination signal while the child drains is a no-op: the
#    drain still finishes (final statistics, flushed and closed report
#    files, .sem marker), a different second signal still exits right away;
#    checked offline without CAP_NET_RAW and, when NET_RAW_IMAGE names an
#    image built from test/double-signal/Dockerfile, online on the
#    container's loopback;
#  - every refused configuration exits EXIT_STATUS_NO_RESTART (3), never 1,
#    while a real crash still dies by its signal (134/139 from a shell);
#  - "docker stop" on a probe container exits 0 quickly - only when
#    DOCKER_IMAGE names an image holding this probe and a docker daemon is
#    reachable.
#
# The live-capture checks need an effective CAP_NET_RAW on the interface;
# without one they are skipped cleanly, like check_snaplen.sh - the
# capability-independent checks (the start-up error, the offline
# double-signal and refusal legs and, when configured, the docker checks)
# still run.
#
# Run from the repository root after `make ... compile`, e.g.:
#   make test-online-signals
# or directly (the probe must be able to capture on IFACE, i.e. CAP_NET_RAW):
#   sh test/online_signals.sh
#
# Environment overrides:
#   PROBE        probe binary            (default: <repo>/probe)
#   CONF         probe configuration     (default: <repo>/mmt-probe.conf)
#   PCAP         check pcap for the offline legs
#                (default: <repo>/test/UA-Exp01.pcap)
#   ROOT         repository root mounted by the docker-stop check's
#                sibling container       (default: <repo>)
#   IFACE        capture interface       (default: lo)
#   REPEAT_TERM  repeats of the monitor-SIGTERM check (default: 1)
#   GROUP_KILL   repeats of the group-kill check      (default: 10)
#   DBSIG_FRAMES frames in the generated sessions pcap - roughly one
#                distinct session each, which is what gives the offline
#                drain its length       (default: 300000)
#   NET_RAW_IMAGE image for the online double-signal leg, built from
#                test/double-signal/Dockerfile with the probe to check
#                (default: skip)
#   DOCKER_IMAGE image for the docker-stop check (default: skip)
#   CC           compiler for wait_fate  (default: cc)

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$SELF_DIR/.." && pwd)}

PROBE=${PROBE:-"$ROOT/probe"}
CONF=${CONF:-"$ROOT/mmt-probe.conf"}
PCAP=${PCAP:-"$ROOT/test/UA-Exp01.pcap"}
IFACE=${IFACE:-lo}
REPEAT_TERM=${REPEAT_TERM:-1}
GROUP_KILL=${GROUP_KILL:-10}
DBSIG_FRAMES=${DBSIG_FRAMES:-300000}
DOCKER_IMAGE=${DOCKER_IMAGE:-}
NET_RAW_IMAGE=${NET_RAW_IMAGE:-}
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

# the dynamic-conf control child's pid, when the probe was built with
# DYNAMIC_CONFIG_MODULE and it is enabled: the pid in the last matching
# "Create a new sub-process" line of the supervisor's log
control_pid() {
	sed -n 's/.*Create a new sub-process \([0-9][0-9]*\) for dynamic configuration server/\1/p' \
		"$1" | tail -n 1
}

# nb_processing_children <log>: how many processing children the supervisor
# created. "for main processing" keeps the count to the processing child:
# a dynamic-conf build logs matching "... for dynamic configuration server"
# lines that must not count as restarts
nb_processing_children() {
	grep -c "Create a new sub-process .*for main processing" "$1"
}

# no_orphans <pid>...: every pid must be fully gone (no zombie, no stray)
no_orphans() {
	for p in "$@"; do
		[ -n "$p" ] || continue
		[ -e "/proc/$p" ] 2>/dev/null && { bad "orphan process left: $p"; return 1; }
	done
	return 0
}

# wait_pid <name> <pid> [pid...]: wait for <pid> with a watchdog like the
# crash test; returns the exit status in $RC, -1 on watchdog kill. On a
# hang the watchdog kills <pid> and every extra pid - the recorded
# supervisor and its children - so a hung run never orphans the probe
# (only fires on failure).
wait_pid() {
	name=$1; pid=$2; shift 2
	(
		sleep_pid=
		trap '[ -n "$sleep_pid" ] && kill "$sleep_pid" 2>/dev/null; exit 1' TERM
		sleep 15 & sleep_pid=$!
		wait "$sleep_pid" 2>/dev/null
		for p in "$pid" "$@"; do
			[ -n "$p" ] && kill -9 "$p" 2>/dev/null
		done
	) &
	wd=$!
	wait "$pid"
	RC=$?
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ "$RC" = 137 ]; then
		bad "$name: probe did not exit within 15 s (watchdog killed it)"
		RC=-1
	fi
}

# wait_wrapper <name> [pid...]: same wait on the wait_fate wrapper's pid
wait_wrapper() {
	name=$1; shift
	wait_pid "$name" "$WRAPPER_PID" "$@"
}

# check_reports <name> [dir]: the reports written before the signal must
# be flushed. A *.sem file is the probe's zero-byte "file complete" marker
# and sample files are created eagerly, so only non-empty files are
# checked for a terminating newline; at least one file must hold flushed
# data. dir defaults to $WORK/reports.
# _cr_* names: sh has no function scope, a plain 'dir' would clobber a
# caller's variable of the same name
check_reports() {
	_cr_dir=${2:-$WORK/reports}
	nb=$(find "$_cr_dir" -type f ! -name '*.sem' 2>/dev/null | wc -l)
	if [ "$nb" -eq 0 ]; then
		bad "$1: no report file was written"
		return
	fi
	nb_data=0
	nb_bad=0
	for f in "$_cr_dir"/*; do
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

# check_signal_lines <name> <log>: every line carrying a fragment of a
# signal report must be one whole report. The handler composes its
# message in one buffer and emits it in a single write(), so concurrent
# reports from the two children cannot interleave their parts inside a
# line; a fragment-holding line that is not a complete report means the
# writes of two processes interleaved on the shared descriptor. The
# monitor's own "Received signal <n>. Stopping MMT-Probe ..." line shares
# a report fragment, so it is whitelisted below beside the reports.
check_signal_lines() {
	#a missing or empty log must fail too: grep would print an error and
	# leave nb_frag/nb_whole empty, and "" = "" would pass vacuously below
	[ -s "$2" ] || { bad "$1: no signal log line found"; return 1; }
	nb_frag=$(grep -c \
		-e "Received SIG" -e "Received signal" -e "releasing resource" \
		-e "Exit dynamic configuration server" -e "while processing other one" \
		-e "Segv signal received" -e "crash signal received" \
		-e "Abort signal received" -e "Restart signal received" \
		-e "Cleaning up before" "$2" || true)
	nb_whole=$(grep -cx \
		-e "mmt-probe: Received SIGINT\. Main processing process is releasing resource \.\.\." \
		-e "mmt-probe: Received SIGTERM\. Main processing process is releasing resource \.\.\." \
		-e "mmt-probe: Received signal [0-9]*\. Exit dynamic configuration server\." \
		-e "mmt-probe: Received signal [0-9]* while processing other one\. Exit immediately\." \
		-e "mmt-probe: Received signal [0-9]*\. Stopping MMT-Probe \.\.\." \
		-e "mmt-probe: Segv signal received on control process!" \
		-e "mmt-probe: crash signal received: [0-9]*" \
		-e "mmt-probe: Abort signal received! Cleaning up before exiting!" \
		-e "mmt-probe: Restart signal received! Cleaning up before restarting!" \
		"$2" || true)
	#a log without any fragment would pass the equality below vacuously:
	# zero signal lines means the run produced nothing to check
	if [ "$nb_frag" -eq 0 ]; then
		bad "$1: no signal log line found"
		return 1
	fi
	if [ "$nb_frag" = "$nb_whole" ]; then
		pass "$1: $nb_whole signal log line(s) whole"
		return 0
	fi
	bad "$1: $((nb_frag - nb_whole)) of $nb_frag signal log line(s) interleaved:"
	grep \
		-e "Received SIG" -e "Received signal" -e "releasing resource" \
		-e "Exit dynamic configuration server" -e "while processing other one" \
		-e "Segv signal received" -e "crash signal received" \
		-e "Abort signal received" -e "Restart signal received" \
		-e "Cleaning up before" "$2" \
	| grep -vx \
		-e "mmt-probe: Received SIGINT\. Main processing process is releasing resource \.\.\." \
		-e "mmt-probe: Received SIGTERM\. Main processing process is releasing resource \.\.\." \
		-e "mmt-probe: Received signal [0-9]*\. Exit dynamic configuration server\." \
		-e "mmt-probe: Received signal [0-9]* while processing other one\. Exit immediately\." \
		-e "mmt-probe: Received signal [0-9]*\. Stopping MMT-Probe \.\.\." \
		-e "mmt-probe: Segv signal received on control process!" \
		-e "mmt-probe: crash signal received: [0-9]*" \
		-e "mmt-probe: Abort signal received! Cleaning up before exiting!" \
		-e "mmt-probe: Restart signal received! Cleaning up before restarting!" \
	| sed 's/^/    log: /'
	return 1
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
		[ -s "$WORK/pid" ] && sup_pid=$(cat "$WORK/pid" 2>/dev/null)
		kill -9 "$WRAPPER_PID" ${sup_pid:+$sup_pid} 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
		return 1
	fi
	wait_pidfile 50 || {
		bad "$name: no supervisor pid recorded"
		kill -9 "$WRAPPER_PID" 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
		return 1
	}
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
	wait_wrapper "$name" "$sup_pid" "$kid"
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

# 0. capability probe: the live checks need an effective CAP_NET_RAW on
# IFACE - without it the child cannot open the interface and exits with
# the do-not-restart status (that exit is itself check 3 below), so each
# live check would fail where check_snaplen.sh skips them. One short run
# decides; the checks that do not need a live capture still run below.
# The "is running on pid" marker is logged before the capture opens, so a
# probe that cannot capture still prints it and dies a moment later:
# capability is decided by the probe staying alive, not by the marker.
can_capture=0
sup_pid= kid=
logf="$WORK/capability.log"
start_probe "$logf"
#wait until the probe is up, or until it exited on its own (start-up error)
i=0
while [ "$i" -lt 200 ]; do
	grep -q "is running on pid" "$logf" 2>/dev/null && break
	[ -s "$WORK/fate" ] && break
	i=$((i + 1)); sleep 0.1
done
#give a start-up failure a moment to surface after the marker
i=0
while [ "$i" -lt 30 ]; do
	[ -s "$WORK/fate" ] && break
	grep -q "Couldn't open device\|Cannot activate" "$logf" 2>/dev/null && break
	i=$((i + 1)); sleep 0.1
done
if grep -q "Couldn't open device\|Cannot activate" "$logf" 2>/dev/null; then
	#no effective CAP_NET_RAW - skip the live checks like check_snaplen.sh
	say "SKIP: cannot capture on $IFACE (no effective CAP_NET_RAW?)"
	if [ ! -s "$WORK/fate" ]; then
		[ -s "$WORK/pid" ] && sup_pid=$(cat "$WORK/pid" 2>/dev/null)
		kill -9 "$WRAPPER_PID" ${sup_pid:+$sup_pid} 2>/dev/null
		wait "$WRAPPER_PID" 2>/dev/null
	fi
elif [ -s "$WORK/fate" ] || ! grep -q "is running on pid" "$logf" 2>/dev/null; then
	if [ -s "$WORK/fate" ]; then
		bad "capability: probe exited ($(fate)) without capturing"
	else
		bad "capability: no start-up marker and probe still running"
	fi
	tail -n 10 "$logf" | sed 's/^/    log: /'
	kill -9 "$WRAPPER_PID" 2>/dev/null
	wait "$WRAPPER_PID" 2>/dev/null
else
	can_capture=1
	#the probe is up: stop it cleanly before the checks below
	wait_pidfile 50 \
		&& sup_pid=$(cat "$WORK/pid" 2>/dev/null) \
		|| bad "capability: no supervisor pid recorded"
	kid=$(child_pid "$logf")
	if [ -n "$sup_pid" ]; then
		kill -TERM "$sup_pid" 2>/dev/null
	else
		kill -9 "$WRAPPER_PID" 2>/dev/null
	fi
	wait_wrapper "capability" "$sup_pid" "$kid"
fi

if [ "$can_capture" -eq 1 ]; then

# 1. SIGTERM to the supervisor: clean shutdown, repeated
# (rep is used, not i: the helpers above share the caller's i)
rep=0
while [ "$rep" -lt "$REPEAT_TERM" ]; do
	run_shutdown TERM "sigterm-$rep"
	rep=$((rep + 1))
done

# 2. SIGINT to the supervisor: same expectations
run_shutdown INT "sigint"

else
	say "SKIP: SIGTERM/SIGINT checks (cannot capture on $IFACE)"
fi

# 3. a start-up error: the input cannot be used, the child must report the
# do-not-restart status and the monitor must not restart it. This check
# does not need a live capture - opening a nonexistent interface fails the
# same way - so it also runs when the capability probe above skipped.
logf="$WORK/bad-config.log"
: > "$WORK/pid"; : > "$WORK/fate"
"$WORK/wait_fate" "$WORK/pid" "$WORK/fate" \
	"$PROBE" -c "$CONF" -i "i710-no-such-iface" \
	>"$logf" 2>&1 &
WRAPPER_PID=$!
wait_pidfile 50 \
	&& sup_pid=$(cat "$WORK/pid" 2>/dev/null) \
	|| sup_pid=
wait_wrapper "bad-config" "$sup_pid"
if [ "$RC" != -1 ]; then
	check "bad-config status" "$DNR_STATUS" "$RC"
	check "bad-config fate" "exit $DNR_STATUS" "$(fate)"
	grep -q "return code: $DNR_WAIT" "$logf" \
		&& pass "bad-config: monitor saw do-not-restart status" \
		|| bad "bad-config: no do-not-restart marker in log"
	nb=$(nb_processing_children "$logf")
	check "bad-config restarts" 1 "$nb"
fi

# 4. a crash still auto-restarts the processing child
if [ "$can_capture" -eq 1 ]; then
sup_pid= kid= new_kid=
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
				[ "$(nb_processing_children "$logf")" -ge 2 ] && break
				i=$((i + 1)); sleep 0.1
			done
			if [ "$(nb_processing_children "$logf")" -ge 2 ]; then
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
	wait_wrapper "segv-restart" "$sup_pid" "$kid" "$new_kid"
	[ "$RC" = -1 ] || {
		check "segv-restart status" 0 "$RC"
		check "segv-restart fate" "exit 0" "$(fate)"
		no_orphans "$sup_pid" "$kid" "$new_kid"
	}
fi
else
	say "SKIP: segv-restart check (cannot capture on $IFACE)"
fi

# 5. group kill on a dynamic-conf build: a SIGINT to the probe's whole
# process group - the systemd KillMode=control-group shape - reaches the
# monitor AND the children directly, while the monitor's own forward
# reaches them a second time; a SIGTERM to the monitor adds a different
# second signal. The children must exit 0 immediately without deadlocking
# the drain. Only when the probe binary was built with
# DYNAMIC_CONFIG_MODULE and can capture on IFACE.
if [ "$can_capture" -eq 1 ] \
	&& "$PROBE" -v 2>&1 | grep -q "DYNAMIC_CONF" \
	&& command -v setsid >/dev/null 2>&1; then
	# (rep is used, not i: the helpers above share the caller's i)
	rep=0
	while [ "$rep" -lt "$GROUP_KILL" ]; do
		name="group-kill-$rep"
		logf="$WORK/$name.log"
		rm -f "$WORK"/reports/* "$WORK/mmt-$rep.sock"
		#setsid puts the probe tree in its own process group so the group
		# kill reaches the supervisor and both children but not this script.
		# The probe runs directly (no wait_fate: the group kill would hit
		# it); sup_pid is the supervisor itself
		setsid "$PROBE" -c "$CONF" -i "$IFACE" \
			-X "dynamic-config.enable=true" \
			-X "dynamic-config.descriptor=$WORK/mmt-$rep.sock" \
			-X "file-output.output-dir=$WORK/reports/" \
			-X "stats-period=2" \
			-X "output.cache-period=2" \
			>"$logf" 2>&1 &
		sup_pid=$!
		if ! wait_grep "is running on pid" "$logf" 200; then
			bad "$name: no start-up marker in log"
			kill -9 "$sup_pid" 2>/dev/null
			wait "$sup_pid" 2>/dev/null
		elif ! wait_grep "for dynamic configuration server" "$logf" 100; then
			bad "$name: control child did not start"
			kill -TERM "$sup_pid" 2>/dev/null
			wait_pid "$name" "$sup_pid"
		else
			kid=$(child_pid "$logf")
			ctl_pid=$(control_pid "$logf")
			#group SIGINT to every process of the probe's group - which the
			# monitor forwards a second time - plus a SIGTERM for the
			# monitor to forward as a different second signal
			kill -INT -"$sup_pid" 2>/dev/null
			kill -TERM "$sup_pid" 2>/dev/null
			wait_pid "$name" "$sup_pid" "$kid" "$ctl_pid"
			if [ "$RC" != -1 ]; then
				check "$name status" 0 "$RC"
				no_orphans "$sup_pid" "$kid" "$ctl_pid"
				check_signal_lines "$name" "$logf"
			fi
		fi
		rep=$((rep + 1))
	done
else
	if [ "$can_capture" -ne 1 ]; then
		say "SKIP: group-kill checks (cannot capture on $IFACE)"
	elif ! "$PROBE" -v 2>&1 | grep -q "DYNAMIC_CONF"; then
		say "SKIP: group-kill checks (probe built without DYNAMIC_CONFIG_MODULE)"
	elif ! command -v setsid >/dev/null 2>&1; then
		say "SKIP: group-kill checks (setsid not found)"
	fi
fi

# 6. issue #45 - a repeated termination signal while the child drains.
# A group-wide Ctrl+C reaches the processing child directly AND again
# through the monitor's forward (systemd's KillMode=control-group does the
# same with SIGTERM): the repeat used to take the is_exiting branch and
# _exit(0) mid-drain, skipping the security drain, the output fclose/.sem
# and the stdio flush. The child now treats a repeat of the signal it is
# handling as a no-op, so the drain finishes; a different second signal
# still exits right away (that path is unit-tested by test-double-signal).
#
# The offline legs need no CAP_NET_RAW: the same handler branch runs when
# a pcap replay is interrupted. Each run signals mid-capture and repeats
# while is_exiting is set; the assertions are that the drain ran to the
# end - the final statistics are logged, no "while processing other one"
# immediate-exit line is printed for a repeat, every in-flight sampled
# file has its .sem marker and every non-empty report ends with a
# newline. On the unfixed code a repeat exits before or inside the drain,
# so the markers, the .sem and the drained reports are missing.
#
# The drain's length is what makes a repeat land inside it, and it scales
# with the live sessions left to flush - so the legs replay a generated
# pcap of mostly-distinct sessions rather than a repeated capture of a
# few flows.

# a pcap of DBSIG_FRAMES frames, each a mostly-distinct UDP session -
# generated like test/alert-delivery/gen_pcap.py
LONG="$WORK/dbsig-sessions.pcap"
if command -v python3 >/dev/null 2>&1; then
	python3 - "$LONG" "$DBSIG_FRAMES" <<'PYEOF'
import struct, sys
sys.path.insert(0, "test/alert-delivery")
import gen_pcap as g

def sess_frame(i):
    #one mostly-distinct UDP session per frame
    src = 0xC6120000 | ((i // 55000) % 64)
    dst = 0xC6130000 | (i % 64)
    payload = struct.pack(">Q", i) + bytes(24)
    udp = struct.pack(">HHHH", 40000 + (i % 20000),
                     10000 + (i % 55000), 8 + len(payload), 0) + payload
    ck = g._l4_checksum(17, src, dst, udp) or 0xFFFF
    udp = udp[:6] + struct.pack(">H", ck) + udp[8:]
    return g.ETH + g._ipv4(17, src, dst, udp)

out, n = sys.argv[1], int(sys.argv[2])
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i in range(n):
        frame = sess_frame(i)
        f.write(struct.pack("<IIII", g.T0 + i // 1000, i % 1000,
                            len(frame), len(frame)))
        f.write(frame)
PYEOF
	say "double-signal sessions pcap: $(wc -c < "$LONG") bytes"
else
	say "SKIP: dbsig offline legs (python3 not found)"
fi

# start_offline <name>: start the offline probe through wait_fate on the
# long pcap with a sampled file output; no periodic flush or rotation
# (huge periods), one worker, so every report sits in stdio buffers or in
# the drain until the very end - which is what a skipped drain loses
start_offline() {
	name=$1
	mkdir -p "$WORK/$name/reports"
	: > "$WORK/$name/pid"
	: > "$WORK/$name/fate"
	"$WORK/wait_fate" "$WORK/$name/pid" "$WORK/$name/fate" \
		"$PROBE" -c "$CONF" -t "$LONG" \
		-X "file-output.enable=true" \
		-X "file-output.sample-file=true" \
		-X "file-output.output-dir=$WORK/$name/reports/" \
		-X "stats-period=3600" -X "output.cache-period=3600" \
		-X "thread-nb=0" -X "session-report.enable=true" \
		>"$WORK/$name/log" 2>&1 &
	WRAPPER_PID=$!
}

# wait for "is running on pid" then for the probe's pid file
offline_pid() { # <name>
	wait_grep "is running on pid" "$WORK/$1/log" 200 || return 1
	i=0
	while [ "$i" -lt 50 ] && [ ! -s "$WORK/$1/pid" ]; do
		i=$((i + 1)); sleep 0.1
	done
	[ -s "$WORK/$1/pid" ] || return 1
	cat "$WORK/$1/pid"
}

# the leg: a first signal mid-capture, then repeats spread over the rest
# of the run - is_exiting stays set from the first handler until the
# process exits, so every repeat takes the second-signal branch, whether
# it lands while the first handler is still running (pending, delivered
# at its return) or inside the drain. On the unfixed code the first one
# to land exits immediately; on the fixed probe they are all no-ops.
repeat_signal() { # <pid> <sig> <count>
	_i=0
	while [ "$_i" -lt "$3" ]; do
		kill -"$2" "$1" 2>/dev/null || return
		sleep 0.005
		_i=$((_i + 1))
	done
}

# drain_assertions <name> <log> <report-dir>: the checks that fail on the
# unfixed code because the second signal exits before or inside the drain
# (_dr_* names for the same reason as check_reports)
drain_assertions() {
	_dr_name=$1 _dr_log=$2 _dr_dir=$3
	#the final statistics only print while the drain runs
	grep -q "processed" "$_dr_log" \
		&& pass "$_dr_name: final statistics logged" \
		|| bad "$_dr_name: drain skipped - no final statistics"
	#a repeat of the signal being handled must not even report the
	# immediate exit - on the unfixed code this line is present
	grep -q "while processing other one" "$_dr_log" \
		&& bad "$_dr_name: second signal forced the immediate exit" \
		|| pass "$_dr_name: no immediate-exit on a repeated signal"
	#the file open at shutdown is closed and marked complete by the drain
	find "$_dr_dir" -name '*.sem' -type f | grep -q . \
		&& pass "$_dr_name: .sem marker written" \
		|| bad "$_dr_name: no .sem marker - output files not closed"
	check_reports "$_dr_name" "$_dr_dir"
}

if [ -s "$LONG" ]; then

# reference run: a single SIGINT mid-capture drains normally
start_offline "dbsig-ref"
ppid=$(offline_pid "dbsig-ref") || ppid=
if [ -z "$ppid" ]; then
	bad "dbsig-ref: probe did not start"
else
	sleep 0.2
	kill -INT "$ppid" 2>/dev/null || true
	wait_pid "dbsig-ref" "$WRAPPER_PID"
	check "dbsig-ref status" 0 "$RC"
	check "dbsig-ref fate" "exit 0" "$(cat "$WORK/dbsig-ref/fate" 2>/dev/null)"
fi

start_offline "dbsig-int"
ppid=$(offline_pid "dbsig-int") || ppid=
if [ -z "$ppid" ]; then
	bad "dbsig-int: probe did not start"
else
	kill -INT "$ppid" 2>/dev/null || true
	repeat_signal "$ppid" INT 200
	wait_pid "dbsig-int" "$WRAPPER_PID" "$ppid"
	if [ "$RC" = -1 ]; then
		: #the watchdog already failed the leg
	else
		check "dbsig-int status" 0 "$RC"
		check "dbsig-int fate" "exit 0" "$(cat "$WORK/dbsig-int/fate" 2>/dev/null)"
		drain_assertions "dbsig-int" "$WORK/dbsig-int/log" "$WORK/dbsig-int/reports"
	fi
fi

# same leg with SIGTERM
start_offline "dbsig-term"
ppid=$(offline_pid "dbsig-term") || ppid=
if [ -z "$ppid" ]; then
	bad "dbsig-term: probe did not start"
else
	kill -TERM "$ppid" 2>/dev/null || true
	repeat_signal "$ppid" TERM 200
	wait_pid "dbsig-term" "$WRAPPER_PID" "$ppid"
	if [ "$RC" != -1 ]; then
		check "dbsig-term status" 0 "$RC"
		check "dbsig-term fate" "exit 0" "$(cat "$WORK/dbsig-term/fate" 2>/dev/null)"
		drain_assertions "dbsig-term" "$WORK/dbsig-term/log" "$WORK/dbsig-term/reports"
	fi
fi

fi #dbsig offline legs need the generated sessions pcap

# the security leg: alerts are raised early in the capture and written
# during the drain - a skipped drain loses them, so the written count is
# lower than the alerts the engine says it raised (and than the pcap's
# deterministic rule-13 count). Only on a SECURITY_MODULE build with the
# rule set installed.
if "$PROBE" -v 2>&1 | grep -q "SECURITY" && command -v python3 >/dev/null 2>&1; then
	DBSIG_PCAP="$WORK/dbsig-sec.pcap"
	python3 - "$DBSIG_PCAP" <<'PYEOF'
import struct, sys
sys.path.insert(0, "test/alert-delivery")
import gen_pcap as g
out = sys.argv[1]
ALERTS, BENIGN = 200, 120000
frames = [g._syn_with_data_frame(i) for i in range(1, ALERTS + 1)]
frames += [g._udp_frame(i) for i in range(BENIGN)]
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, frame in enumerate(frames):
        ts_us = n * 1000
        f.write(struct.pack("<IIII",
            g.T0 + ts_us // 1000000, ts_us % 1000000, len(frame), len(frame)))
        f.write(frame)
PYEOF
	if [ -s "$DBSIG_PCAP" ]; then
		dir="$WORK/dbsig-sec"
		mkdir -p "$dir/reports"
		#conf styled on test/alert-delivery's: the security reports go to
		# the sampled file output; huge periods mean only the drain flushes
		cat > "$dir/probe.conf" <<EOF
probe-id = 3
stack-type = 1
stack-offset = 0
stats-period = 3600
input {
	mode = OFFLINE
	source = "$DBSIG_PCAP"
	snap-len = 0
}
output {
	format = CSV
	cache-max = 100000
	cache-period = 3600
}
file-output {
	enable = true
	output-file = "data.csv"
	output-dir = "$dir/reports/"
	sample-file = true
	retain-files = 0
}
thread-nb = 0
thread-queue = 1024
security {
	enable = true
	thread-nb = 0
	exclude-rules = ""
	rules-mask = ""
	output-channel = {file}
	report-rule-description = true
	ignore-remain-flow = true
	input.max-message-size = 60000
	security.max-instances = 100000
	security.smp.ring-size = 1000
}
session-report {
	enable = true
	output-channel = {file}
}
EOF
		: > "$dir/pid"; : > "$dir/fate"
		"$WORK/wait_fate" "$dir/pid" "$dir/fate" \
			"$PROBE" -c "$dir/probe.conf" >"$dir/log" 2>&1 &
		WRAPPER_PID=$!
		ppid=$(offline_pid "dbsig-sec") || ppid=
		if [ -z "$ppid" ]; then
			bad "dbsig-sec: probe did not start"
		else
			#the 200 alerts are raised in the first frames and still
			# buffered or in the engine when the repeats land: a skipped
			# drain loses them
			kill -INT "$ppid" 2>/dev/null || true
			repeat_signal "$ppid" INT 200
			wait_pid "dbsig-sec" "$WRAPPER_PID" "$ppid"
			if [ "$RC" != -1 ]; then
				check "dbsig-sec status" 0 "$RC"
				check "dbsig-sec fate" "exit 0" \
					"$(cat "$dir/fate" 2>/dev/null)"
				drain_assertions "dbsig-sec" "$dir/log" "$dir/reports"
				raised=$(grep -E 'processed .* generated [0-9]+ alerts' \
					"$dir/log" | \
					sed 's/.* generated \([0-9]*\) alerts.*/\1/' | \
					awk '{ s += $1 } END { print s + 0 }')
				#written alerts, in whichever shape the build emits:
				# STIX bundles on a STIX_FORMAT build, report-type-10
				# rows otherwise - same counting as check_alert_delivery
				written=$(cat "$dir"/reports/* 2>/dev/null | \
					grep -cE '"type": "bundle"|^\[?10,')
				check "dbsig-sec alerts raised == written" \
					"$raised" "$written"
				[ "$raised" -gt 0 ] \
					|| bad "dbsig-sec: the engine raised no alert"
			fi
		fi
	else
		bad "dbsig-sec: cannot generate the capture"
	fi
else
	if ! "$PROBE" -v 2>&1 | grep -q "SECURITY"; then
		say "SKIP: dbsig-sec (probe built without SECURITY_MODULE)"
	else
		say "SKIP: dbsig-sec (python3 not found)"
	fi
fi

# the online leg inside a container: the probe binary baked into
# NET_RAW_IMAGE carries cap_net_raw, so the unprivileged container user can
# capture on the container's loopback. The inner script replays the
# monitor-forward scenario: a group SIGINT hits the child directly and
# through the monitor's forward while the drain has live work. The conf is
# a self-contained online capture on IFACE; on a SECURITY_MODULE build it
# also enables the security engine so the drain's alert delivery is
# checked too.
if [ -n "$NET_RAW_IMAGE" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	indir="$WORK/container-in"
	mkdir -p "$indir"
	#a self-contained conf for the inner run: online capture on the
	# container's loopback, sampled file output under /work
	cat > "$indir/probe-inner.conf" <<EOF
probe-id = 3
stack-type = 1
stack-offset = 0
stats-period = 3600
input {
	mode = ONLINE
	source = "$IFACE"
	snap-len = 0
}
output {
	format = CSV
	cache-max = 100000
	cache-period = 3600
}
file-output {
	enable = true
	output-file = "data.csv"
	output-dir = "/work/reports/"
	sample-file = true
	retain-files = 0
}
thread-nb = 0
thread-queue = 1024
session-report {
	enable = true
	output-channel = {file}
}
EOF
	if "$PROBE" -v 2>&1 | grep -q "SECURITY"; then
		cat >> "$indir/probe-inner.conf" <<'EOF'
security {
	enable = true
	thread-nb = 0
	exclude-rules = ""
	rules-mask = ""
	output-channel = {file}
	report-rule-description = true
	ignore-remain-flow = true
	input.max-message-size = 60000
	security.max-instances = 100000
	security.smp.ring-size = 1000
}
EOF
	fi
	#the inner run reports into /work (= $indir) for the host to check
	if timeout -s KILL 120 docker run --rm --name "f57m-dbsig-$$" \
		--memory 4g --memory-swap 4g --pids-limit 512 \
		--user "$(id -u):$(id -g)" \
		-v "$indir:/work" \
		-e "CONF=/work/probe-inner.conf" \
		--entrypoint /bin/sh \
		"$NET_RAW_IMAGE" /opt/inner_container.sh; then
		:
	else
		bad "dbsig-online: container run failed"
	fi
	if [ -s "$indir/verdict" ]; then
		while IFS= read -r line; do
			case "$line" in
			PASS*) pass "dbsig-online: ${line#PASS: }" ;;
			FAIL*) bad "dbsig-online: ${line#FAIL: }" ;;
			*) say "dbsig-online: $line" ;;
			esac
		done < "$indir/verdict"
		check_reports "dbsig-online" "$indir/reports"
	else
		bad "dbsig-online: no verdict from the container"
		sed 's/^/    log: /' "$indir/log" 2>/dev/null | tail -20
	fi
else
	say "SKIP: dbsig-online (set NET_RAW_IMAGE to the image built from test/double-signal/Dockerfile)"
fi

# 7. docker stop on a containerized probe: exits 0, well under the 10 s
# grace period - only when an image and a daemon are provided. The
# container runs with --rm; a docker wait subscribed before the stop still
# reports the exit code once the container is gone.
if [ -n "$DOCKER_IMAGE" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	name="f57m-stop-$$"
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

# 8. issue #45 - every refused configuration exits EXIT_STATUS_NO_RESTART
# (3), the status mmt-probe.service lists under RestartPreventExitStatus=,
# never EXIT_FAILURE (1) which the service would restart forever. The
# checks run the probe directly: a refusal exits inside _parse_options
# before the monitor forks, so no capture capability is needed. Real
# crashes still die by their signal (crash_exit_status.sh checks the
# 139/134/... fates offline).
expect_dnr() { # <name> <probe-args...>
	name=$1; shift
	timeout -s KILL 30 "$PROBE" "$@" >"$WORK/$name.log" 2>&1
	rc=$?
	check "$name status" "$DNR_STATUS" "$rc"
	if grep -qiE 'crash signal received|AddressSanitizer|runtime error:' "$WORK/$name.log"; then
		bad "$name: crash report in the log of a refused configuration"
	fi
}

#an unreadable configuration file is refused
expect_dnr "refuse-missing-conf" -c "$WORK/no-such.conf" -t "$PCAP"

#a malformed configuration file is not a refusal: libconfuse tolerates an
# unclosed block, so a truncated conf reaches capture setup and dies by
# abort() like any real crash - crash_exit_status.sh pins that fate. The
# refusal legs below are the ones _parse_options can reject cleanly.

#a configuration that fails conf_validate is refused - file-output
# enabled without an output file
expect_dnr "refuse-invalid-conf" -c "$CONF" -t "$PCAP" \
	-X "file-output.enable=true" -X "file-output.output-file="

#an -X option value outside the accepted range or format is refused
expect_dnr "refuse-bad-x" -c "$CONF" -t "$PCAP" -X "output.format=BOGUS"

#an -X option naming a parameter that does not exist is refused
expect_dnr "refuse-unknown-x" -c "$CONF" -t "$PCAP" -X "no.such.ident=1"

#an -X option into a block absent from the conf file is refused
expect_dnr "refuse-no-block-x" -c "$CONF" -t "$PCAP" \
	-X "reconstruct-data.http.output-dir=/tmp/i45-recon"

say "---"
if [ "$fail" -eq 0 ]; then
	say "all checks passed"
else
	say "some checks failed"
fi
exit "$fail"
