#!/bin/sh
# Regression check for the conf_update_output_enable() bug (issue #40): an
# MQTT-only enabled output was not counted in output.is_enable, so
# output_alloc_init() returned NULL and the probe silently dropped every
# report. The check uses a conf whose only enabled output channel is MQTT
# pointed at 127.0.0.1 on a port nothing listens on:
#
#   - the enabled mqtt-output block must make the output exist: session
#     reports appear on the { stdout } channel, and on an MQTT_MODULE
#     build the channel tried to connect and failed gracefully instead of
#     abort()ing at startup;
#   - disabling mqtt-output in the file keeps the run clean (no output at
#     all: no report reaches stdout);
#   - both runs must exit 0 and reach the end of the pcap, never crash.
#
# On the unfixed code the first run produces no stdout report (the output
# was NULL), and on an MQTT_MODULE build it dies by abort() in
# _connect_to_mqtt() before reading any packet.
#
# Usage: check_mqtt_output.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the logs (default: a new mktemp -d,
#            removed on exit)
# Overrides via env: RUN_TIMEOUT, PCAP.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUN_TIMEOUT=${RUN_TIMEOUT:-120}

#when the probe is built with sanitizers: a clean run must report nothing;
# leak reports are out of scope for this check
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-mqtt-output.XXXXXX")
	CLEAN=1
else
	mkdir -p "$WORK_DIR"
fi
cleanup() {
	[ "$CLEAN" -eq 1 ] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 2
}

[ -x "$PROBE" ] || fail "probe binary not found or not executable: $PROBE"
[ -f "$CONF" ]  || fail "conf file not found: $CONF"
[ -f "$PCAP" ]  || fail "pcap file not found: $PCAP"

nb_fail=0
nb_run=0

#a CSV report line printed on the stdout output channel:
# report_type,probe_id,"input_source",timestamp,...
count_reports() {
	grep -cE '^[0-9]+,1,"' "$1" 2>/dev/null || true
}

crashed() {
	grep -qiE 'crash signal received|Segmentation fault|runtime error|AddressSanitizer' "$1"
}

#the modules compiled in, for the module-only assertions
MODULES=$("$PROBE" -v 2>&1)

echo "check_mqtt_output: probe=$PROBE conf=$CONF pcap=$PCAP"

#an MQTT-only output must be allocated: the probe runs to the end of the
# pcap and the session reports reach stdout
nb_run=$((nb_run + 1))
log="$WORK_DIR/run-mqtt-only.log"
timeout -s KILL "$RUN_TIMEOUT" "$PROBE" -c "$CONF" -t "$PCAP" >"$log" 2>&1
rc=$?

problems=""
[ "$rc" -eq 0 ] || problems="$problems exit=$rc"
grep -q "reached to the end of pcap file" "$log" || problems="$problems no-eof"
[ "$(count_reports "$log")" -gt 0 ] || problems="$problems no-report-on-stdout"
crashed "$log" && problems="$problems crashed"
if printf '%s\n' "$MODULES" | grep -q MQTT; then
	#the channel was actually inited and the failed connect did not kill
	# the probe
	grep -q "connect MQTT to" "$log" || problems="$problems no-connect-attempt"
fi
if [ -z "$problems" ]; then
	echo "PASS run-mqtt-only"
else
	nb_fail=$((nb_fail + 1))
	echo "FAIL run-mqtt-only:$problems (log: $log)"
fi

#with the channel disabled there is no output left: the run is still
# clean and nothing reaches stdout. A conf variant, not -X, flips the
# flag: 'mqtt-output.enable' is not an -X identity on a non-MQTT build
nb_run=$((nb_run + 1))
sed '/mqtt-output {/,/}/ s/enable *= *true/enable = false/' \
	"$CONF" > "$WORK_DIR/mqtt-off.conf"
log="$WORK_DIR/run-mqtt-off.log"
timeout -s KILL "$RUN_TIMEOUT" "$PROBE" -c "$WORK_DIR/mqtt-off.conf" \
	-t "$PCAP" >"$log" 2>&1
rc=$?

problems=""
[ "$rc" -eq 0 ] || problems="$problems exit=$rc"
grep -q "reached to the end of pcap file" "$log" || problems="$problems no-eof"
[ "$(count_reports "$log")" -eq 0 ] || problems="$problems unexpected-report"
crashed "$log" && problems="$problems crashed"
if [ -z "$problems" ]; then
	echo "PASS run-mqtt-off"
else
	nb_fail=$((nb_fail + 1))
	echo "FAIL run-mqtt-off:$problems (log: $log)"
fi

echo "check_mqtt_output: $nb_run run(s), $nb_fail failure(s)"
[ "$nb_fail" -eq 0 ]
