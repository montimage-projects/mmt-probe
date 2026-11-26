#!/bin/sh
# Regression check for issue #49: 'system-report.period' was parsed into
# conf->reports.cpu_mem->frequency but never used - the system-stats
# routine fired the type-201 report on a hardcoded 'timer_1 == 5', and the
# line reading the configured frequency was commented out. Setting any
# period had no effect.
#
# Legs:
#   - 'period = 2' in the configuration file and through
#     '-X system-report.period=2': the pcap is fed through a FIFO held open
#     HOLD seconds, and at least 3 type-201 reports must be written (a 5 s
#     cadence gives at most 2 in that window);
#   - no 'period' line, and 'period = 0' (the parser's "unset" value): the
#     default cadence of 5 s applies, exactly 2 reports in HOLD seconds;
#   - refused values: 'period = -1' and 'period = 70000' in the
#     configuration file are rejected with an error naming
#     'system-report.period'; '-X system-report.period=' of 0, -1, abc and
#     70000 is rejected with the do-not-restart status 3 - the field is a
#     uint16_t and a value that does not fit would wrap into a different
#     cadence;
#   - '-x' still lists the key with its type.
#
# On the unfixed code the cadence legs see only the hardcoded 5 s cadence
# (2 reports in HOLD seconds, not >= 3) and the refused values are either
# wrapped silently or - for 0 through -X - accepted, so the check fails.
#
# Usage: check_sysreport_period.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the generated confs, reports and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: RUN_TIMEOUT, HOLD, PCAP.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUN_TIMEOUT=${RUN_TIMEOUT:-120}
#seconds the pcap stream stays open after the packets: long enough for a
# 2 s cadence to fire at least 3 times and for the default 5 s cadence to
# fire exactly twice
HOLD=${HOLD:-12}

#when the probe is built with sanitizers: leak reports are out of scope
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-sysreport-period.XXXXXX")
	CLEAN=1
else
	mkdir -p "$WORK_DIR"
fi
cleanup() {
	if [ "$CLEAN" -eq 1 ]; then
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 2
}

[ -x "$PROBE" ] || fail "probe binary not found or not executable: $PROBE"
[ -f "$PCAP" ]  || fail "pcap file not found: $PCAP"
[ -f "$CONF" ]  || fail "configuration not found: $CONF"

TIMEOUT=
if command -v timeout >/dev/null 2>&1; then
	TIMEOUT="timeout -s KILL $RUN_TIMEOUT"
fi

nb_fail=0
nb_run=0

pass() { echo "  PASS $1"; }
bad()  { echo "  FAIL $1: $2"; nb_fail=$((nb_fail + 1)); }

#write the configuration of case $1 into $WORK_DIR/$1/probe.conf; $2
# replaces the 'period' line of the system-report block ('none' removes it,
# so the parser's default applies). The file output is enabled so the
# output subsystem exists (stdout alone does not enable it): the {stdout}
# channel of the system-report block then also writes the report rows.
make_conf() {
	dir=$WORK_DIR/$1
	rm -rf "$dir"
	mkdir -p "$dir/out"
	if [ "${2:-}" = "none" ]; then
		grep -v '^[[:space:]]*period' "$CONF" > "$dir/probe.conf"
	elif [ -n "${2:-}" ]; then
		sed "s|^\(\s*\)period\s*=\s*5|\1period = $2|" "$CONF" > "$dir/probe.conf"
	else
		cp "$CONF" "$dir/probe.conf"
	fi
	cat >> "$dir/probe.conf" <<-EOF
	file-output {
	    enable       = true
	    output-file  = "data.csv"
	    output-dir   = "$dir/out/"
	    sample-file  = false
	    retain-files = 0
	}
	EOF
	echo "$dir/probe.conf"
}

#the number of type-201 system reports in a run's log
count_reports() {
	grep -c '^201,' "$1" 2>/dev/null || true
}

#a run that must process the pcap and exit 0: the pcap is fed through a
# FIFO kept open $HOLD seconds so the system-stats routine fires several
# times before the stream ends. $1: case name, $2: the 'period' line
# replacement ('none' removes it), $3: extra probe arguments (-X ...),
# $4/$5: bounds on the report count (min/max included)
expect_cadence() {
	name=$1 period=$2 xarg=$3 want_min=$4 want_max=$5
	conf=$(make_conf "$name" "$period")
	fifo=$WORK_DIR/$name/in.fifo
	mkfifo "$fifo"
	( cat "$PCAP"; sleep "$HOLD" ) > "$fifo" &
	writer=$!
	nb_run=$((nb_run + 1))
	status=0
	if [ -n "$xarg" ]; then
		$TIMEOUT "$PROBE" -c "$conf" -t "$fifo" -X "$xarg" \
			> "$WORK_DIR/$name/log" 2>&1 || status=$?
	else
		$TIMEOUT "$PROBE" -c "$conf" -t "$fifo" \
			> "$WORK_DIR/$name/log" 2>&1 || status=$?
	fi
	#the writer may still hold the stream (or be blocked on its open when
	# the probe died before reading): close it so the script never hangs
	kill "$writer" 2>/dev/null || true
	wait "$writer" 2>/dev/null || true

	if [ "$status" -ne 0 ]; then
		bad "$name" "exit status $status, expected 0"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if grep -q 'Sanitizer\|runtime error\|Segmentation fault' "$WORK_DIR/$name/log"; then
		bad "$name" "crash or sanitizer report"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if ! grep -q 'reached to the end of pcap file' "$WORK_DIR/$name/log"; then
		bad "$name" "did not reach the end of the pcap"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	got=$(count_reports "$WORK_DIR/$name/log")
	if [ "$got" -ge "$want_min" ] && [ "$got" -le "$want_max" ]; then
		pass "$name ($got reports in ${HOLD}s)"
	else
		bad "$name" "$got system reports in ${HOLD}s, expected $want_min..$want_max"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	pass "$name"
}

#a run that must be refused before any packet is read, with the
# do-not-restart status 3, never a crash (issue #45: a refused
# configuration no longer exits 1). $1: case name, $2: the 'period' line
# replacement ('none' removes it), $3: extra probe arguments, $4: a
# message the log must show
expect_reject() {
	name=$1 period=$2 xarg=$3 want_msg=$4
	conf=$(make_conf "$name" "$period")
	nb_run=$((nb_run + 1))
	status=0
	if [ -n "$xarg" ]; then
		$TIMEOUT "$PROBE" -c "$conf" -t "$PCAP" -X "$xarg" \
			> "$WORK_DIR/$name/log" 2>&1 || status=$?
	else
		$TIMEOUT "$PROBE" -c "$conf" -t "$PCAP" \
			> "$WORK_DIR/$name/log" 2>&1 || status=$?
	fi

	if [ "$status" -ne 3 ]; then
		bad "$name" "exit status $status, expected 3"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if grep -q 'Segmentation fault\|Sanitizer\|runtime error' "$WORK_DIR/$name/log"; then
		bad "$name" "crash or sanitizer report"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if ! grep -q "$want_msg" "$WORK_DIR/$name/log"; then
		bad "$name" "missing error message: $want_msg"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	pass "$name"
}

echo "[1] a configured period changes the report cadence"
#2 s cadence: at least 3 reports in HOLD s; a 5 s cadence (the hardcoded
# one of the unfixed code) gives at most 2
expect_cadence conf-period-2 "2" ""                        3 1000
expect_cadence X-period-2    "5" "system-report.period=2"  3 1000

echo "[2] an unset period keeps the 5 s default"
#5 s cadence: exactly 2 reports in HOLD s
expect_cadence conf-unset    "none" ""                     2 2
expect_cadence conf-zero     "0" ""                        2 2

echo "[3] refused period values"
expect_reject conf-neg  "-1"    ""                        "system-report.period"
expect_reject conf-big  "70000" ""                        "system-report.period"
expect_reject X-zero    "5" "system-report.period=0"     "Unexpected parameter value"
expect_reject X-neg     "5" "system-report.period=-1"    "Unexpected parameter value"
expect_reject X-abc     "5" "system-report.period=abc"   "Unexpected parameter value"
expect_reject X-big     "5" "system-report.period=70000" "Unexpected parameter value"

echo "[4] -x lists the key with its type"
nb_run=$((nb_run + 1))
"$PROBE" -x > "$WORK_DIR/x.log" 2>&1 || true
if grep -qxF "system-report.period (uint16_t)" "$WORK_DIR/x.log"; then
	pass "x-system-report-period"
else
	bad "x-system-report-period" \
		"-x prints: $(grep '^system-report.period ' "$WORK_DIR/x.log")"
fi

echo "sysreport-period: $nb_run runs, $nb_fail failed"
[ "$nb_fail" -eq 0 ] || exit 1
echo "sysreport-period: all checks passed"
