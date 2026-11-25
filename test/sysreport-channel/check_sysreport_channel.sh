#!/bin/sh
# Regression check for issue #43: 'system-report.output-channel' was
# declared CHAR_STAR while its field is an output_channel_conf_t bitmask,
# so the CHAR_STAR arm of _override_element_by_ident() freed and cloned a
# string into the enum field: '-X system-report.output-channel=file' died
# by SIGSEGV (exit 139). The key is declared LIST like the other
# '*.output-channel' keys, and -X accepts the channel spellings the
# configuration file accepts.
#
# Legs:
#   - '-X system-report.output-channel=file': exit 0, the run reaches the
#     end of the pcap and the system report lands in the file output;
#   - '-X system-report.output-channel=file,stdout' - a list, as the
#     configuration file writes it: the report lands in the file output
#     and on stdout;
#   - a refused 'output-channel' value in the configuration file (a list
#     the parser rejects): non-zero exit, never a crash;
#   - '-x' lists the key like the other '*.output-channel' keys.
#
# The system report is written by a routine thread once every 5 seconds
# (system_stats.c), so each positive leg feeds the pcap through a FIFO
# held open for HOLD seconds: the probe stays alive for one report to
# fire, then sees the end of the stream and exits 0.
#
# On the unfixed code the -X legs die by SIGSEGV during option parsing,
# before any packet is read, so the check fails.
#
# Usage: check_sysreport_channel.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the generated confs, reports and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: RUN_TIMEOUT, HOLD, PCAP.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUN_TIMEOUT=${RUN_TIMEOUT:-120}
#seconds the pcap stream stays open after the packets: must be over 5, the
# period at which the system-stats routine writes one report
HOLD=${HOLD:-8}

#when the probe is built with sanitizers: leak reports are out of scope
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-sysreport-channel.XXXXXX")
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

#write the configuration of case $1 into $WORK_DIR/$1/probe.conf, reporting
# into $WORK_DIR/$1/out/; when $2 is given it replaces the {stdout}
# channel list of the system-report block (the refused leg writes a
# malformed list)
make_conf() {
	dir=$WORK_DIR/$1
	rm -rf "$dir"
	mkdir -p "$dir/out"
	if [ -n "${2:-}" ]; then
		sed "s|output-channel = {stdout}|output-channel = $2|" "$CONF" \
			> "$dir/probe.conf"
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

#a run that must process the pcap and exit 0: the pcap is fed through a
# FIFO kept open $HOLD seconds so the system-stats routine fires once
# before the stream ends. The report file, when one is written, is
# $WORK_DIR/$1/out/*_data.csv and the log $WORK_DIR/$1/log
expect_channel() {
	# $1: case name, $2: the -X channel value, $3: 'yes' when the report
	# must also reach stdout, else 'no'
	name=$1 channel=$2 want_stdout=$3
	conf=$(make_conf "$name")
	fifo=$WORK_DIR/$name/in.fifo
	mkfifo "$fifo"
	( cat "$PCAP"; sleep "$HOLD" ) > "$fifo" &
	writer=$!
	nb_run=$((nb_run + 1))
	status=0
	$TIMEOUT "$PROBE" -c "$conf" -t "$fifo" \
		-X "system-report.output-channel=$channel" \
		> "$WORK_DIR/$name/log" 2>&1 || status=$?
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
	#the system report (type 201) must be in the file output
	if grep -h '^201,' "$WORK_DIR/$name/out/"*_data.csv 2>/dev/null | grep -q .; then
		pass "$name report in file output"
	else
		bad "$name" "no system report in $WORK_DIR/$name/out"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	#and on stdout only when the channel asks for it
	if grep -q '^201,' "$WORK_DIR/$name/log"; then
		got_stdout=yes
	else
		got_stdout=no
	fi
	if [ "$got_stdout" = "$want_stdout" ]; then
		pass "$name stdout=$want_stdout"
	else
		bad "$name" "report on stdout: $got_stdout, expected $want_stdout"
		return
	fi
	pass "$name"
}

#a run that must be refused: non-zero exit, never a crash - the
# configuration file's 'output-channel' holds a malformed list, refused by
# the parser before any packet is read
expect_reject() {
	name=$1
	conf=$(make_conf "$name" "$2")
	nb_run=$((nb_run + 1))
	status=0
	$TIMEOUT "$PROBE" -c "$conf" -t "$PCAP" \
		> "$WORK_DIR/$name/log" 2>&1 || status=$?

	if [ "$status" -eq 0 ]; then
		bad "$name" "accepted, expected a refusal"
		return
	fi
	if grep -q 'Segmentation fault\|Sanitizer\|runtime error' "$WORK_DIR/$name/log"; then
		bad "$name" "crash or sanitizer report"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if ! grep -q 'could not be parsed' "$WORK_DIR/$name/log"; then
		bad "$name" "missing parse error"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	pass "$name"
}

echo "[1] channel spellings the configuration file accepts"
expect_channel X-file        file        no
expect_channel X-file-stdout file,stdout yes

echo "[2] a refused channel value"
expect_reject conf-malformed '{"file}'

echo "[3] -x lists the key like the other channel keys"
nb_run=$((nb_run + 1))
"$PROBE" -x > "$WORK_DIR/x.log" 2>&1 || true
if grep -qxF "system-report.output-channel (string)" "$WORK_DIR/x.log"; then
	pass "x-system-report-output-channel"
else
	bad "x-system-report-output-channel" \
		"-x prints: $(grep '^system-report.output-channel ' "$WORK_DIR/x.log")"
fi

echo "sysreport-channel: $nb_run runs, $nb_fail failed"
[ "$nb_fail" -eq 0 ] || exit 1
echo "sysreport-channel: all checks passed"
