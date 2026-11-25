#!/bin/sh
# Regression check for issue #38: every security alert that MMT-Security
# raises during an offline capture must be written to the report files
# before the probe exits, on every run.
#
# Each leg runs the probe RUNS times on the same capture and checks, run by
# run, that:
#   - the probe exits 0;
#   - the number of security reports written (STIX bundles, plus CSV/JSON
#     security rows on a build without STIX_FORMAT or for a bundle too big
#     for the report buffer) equals the number of alerts the engine says it
#     raised ("... generated N alerts" in the final statistics);
#   - on the generated capture, whose last ALERTS packets are TCP SYN
#     segments carrying data, exactly ALERTS reports of rule 13 ("Data in
#     SYN packet") are written: these alerts are raised at the very end of
#     the capture, while the workers and the security threads stop.
#
# The legs cover the shutdown paths: thread-nb 0 (the main thread is the
# worker) and 1 and 3 (worker threads), with the security engine in the
# worker thread (security.thread-nb = 0) or in 1 or 2 threads of its own,
# CSV and JSON, plain and sampled report files. A last leg replays
# test/UA-Exp01.pcap with 3 workers: there rule 56 (SYN flood) can raise
# an alert on some runs and not on others, because its tables are shared by
# the security threads of all the workers, which reach a given packet time
# in a different order on every run (see issue #38). The leg checks that
# the alerts raised, whatever their number, are all written; it prints how
# many runs raised one.
#
# Usage: check_alert_delivery.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the captures, confs, reports and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: RUNS (runs per leg, default 3), ALERTS (default 12),
# RUN_TIMEOUT (seconds per run, default 120), PCAP (the replayed capture).

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUNS=${RUNS:-3}
ALERTS=${ALERTS:-12}
RUN_TIMEOUT=${RUN_TIMEOUT:-120}

#when the probe is built with sanitizers: a clean run must report nothing;
# leak reports are out of scope for this check
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0}
export UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-alert-delivery.XXXXXX")
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

VERSION=$("$PROBE" -v 2>&1) || fail "'$PROBE -v' failed: $VERSION"
case $VERSION in
*"- MMT-Probe "*) ;;
*) fail "'$PROBE -v' printed no version: $VERSION" ;;
esac
case $VERSION in
*"Modules:"*SECURITY*) ;;
*)
	echo "SKIP alert-delivery (probe built without SECURITY_MODULE)"
	exit 0
	;;
esac
MMT_BASE=$(printf '%s\n' "$VERSION" | sed -n 's/^- MMT_BASE: //p')
if ! ls "${MMT_BASE:-/opt/mmt}"/security/rules/13.*.so > /dev/null 2>&1; then
	echo "SKIP alert-delivery (rule 13 of MMT-Security not installed under ${MMT_BASE:-/opt/mmt}/security/rules)"
	exit 0
fi
#gen_pcap.py builds the capture whose last packets raise the alerts
if ! command -v python3 > /dev/null; then
	echo "SKIP alert-delivery (python3 not found)"
	exit 0
fi

TIMEOUT=
command -v timeout > /dev/null && TIMEOUT="timeout -s KILL $RUN_TIMEOUT"

GEN_PCAP=$WORK_DIR/alerts-at-end.pcap
python3 "$SELF_DIR/gen_pcap.py" "$GEN_PCAP" "$ALERTS" || fail "cannot generate $GEN_PCAP"

nb_fail=0
nb_run=0

# write_conf FILE PCAP OUT_DIR FORMAT THREADS SEC_THREADS SAMPLED
write_conf() {
	cat > "$1" <<EOF
probe-id = 3
stack-type = 1
stack-offset = 0
stats-period = 3600
enable-report-version-info = true
input {
	mode = OFFLINE
	source = "$2"
	snap-len = 0
}
output {
	format = $4
	cache-max = 100000
	cache-period = 5
}
file-output {
	enable = true
	output-file = "data.$4"
	output-dir = "$3/"
	sample-file = $7
	retain-files = 0
}
thread-nb = $5
#small worker rings keep the memory of a run low (a sanitizer build of the
# probe at thread-nb 3 needs over 6 GB with 262144); offline, a full ring
# makes the reader wait, it never drops a packet
thread-queue = 1024
security {
	enable = true
	thread-nb = $6
	exclude-rules = ""
	rules-mask = ""
	output-channel = {file}
	report-rule-description = true
	ignore-remain-flow = true
	input.max-message-size = 60000
	security.max-instances = 100000
	security.smp.ring-size = 1000
	ip-encapsulation-index = LAST
}
session-report {
	enable = true
	output-channel = {file}
}
EOF
}

# security reports in the report files of a run: STIX bundles, plus the
# security rows (report type 10) of the CSV and JSON formats
count_reports() {
	# $1: out dir, $2: optional rule id
	if [ -n "${2:-}" ]; then
		bundles=$(cat "$1"/*data.* 2> /dev/null | grep -c "\"external_id\": \"$2\"")
		rows=$(cat "$1"/*data.* 2> /dev/null | grep -Ec "^\\[?10,[^,]*,\"[^\"]*\",[0-9.]+,$2,")
	else
		bundles=$(cat "$1"/*data.* 2> /dev/null | grep -c '"type": "bundle"')
		rows=$(cat "$1"/*data.* 2> /dev/null | grep -Ec '^\[?10,')
	fi
	echo $((bundles + rows))
}

# leg NAME PCAP FORMAT THREADS SEC_THREADS SAMPLED EXPECTED_RULE13
#   EXPECTED_RULE13 empty: only check that raised == written
leg() {
	name=$1 pcap=$2 format=$3 threads=$4 sec_threads=$5 sampled=$6 expect13=$7
	leg_fail=0 with_alert=0
	i=1
	while [ "$i" -le "$RUNS" ]; do
		nb_run=$((nb_run + 1))
		dir=$WORK_DIR/$name/$i
		mkdir -p "$dir/out"
		write_conf "$dir/probe.conf" "$pcap" "$dir/out" "$format" "$threads" "$sec_threads" "$sampled"
		$TIMEOUT "$PROBE" -c "$dir/probe.conf" > "$dir/log" 2>&1
		rc=$?
		raised=$(grep -E '^mmt-probe: (Worker [0-9]+|MMT) processed .* generated [0-9]+ alerts' "$dir/log" |
			sed 's/.* generated \([0-9]*\) alerts.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
		written=$(count_reports "$dir/out")
		why=
		[ "$rc" -eq 0 ] || why="exit status $rc"
		grep -qE '^mmt-probe: (Worker [0-9]+|MMT) processed' "$dir/log" ||
			why="${why:+$why, }no final statistics"
		[ "$written" -eq "$raised" ] || why="${why:+$why, }$raised alerts raised but $written written"
		if [ -n "$expect13" ]; then
			got13=$(count_reports "$dir/out" 13)
			[ "$got13" -eq "$expect13" ] ||
				why="${why:+$why, }$got13 rule-13 reports written, $expect13 expected"
		fi
		if grep -qE 'ERROR: (AddressSanitizer|ThreadSanitizer|LeakSanitizer)|runtime error:' "$dir/log"; then
			why="${why:+$why, }sanitizer report"
		fi
		[ "$raised" -gt 0 ] && with_alert=$((with_alert + 1))
		if [ -n "$why" ]; then
			echo "FAIL $name run $i: $why (log: $dir/log)"
			[ "$CLEAN" -eq 1 ] && sed 's/^/    /' "$dir/log" | tail -n 20
			leg_fail=1
		fi
		i=$((i + 1))
	done
	if [ "$leg_fail" -eq 0 ]; then
		if [ -n "$expect13" ]; then
			echo "PASS $name: $RUNS/$RUNS runs wrote all $expect13 end-of-capture alerts"
		else
			echo "PASS $name: $RUNS/$RUNS runs wrote every raised alert ($with_alert raised one or more)"
		fi
	else
		nb_fail=$((nb_fail + 1))
	fi
}

echo "[alert-delivery] $RUNS runs per leg, $ALERTS alerts at the end of the generated capture"

leg t0-sec0-csv        "$GEN_PCAP" CSV  0 0 false "$ALERTS"
leg t0-sec1-json       "$GEN_PCAP" JSON 0 1 false "$ALERTS"
leg t1-sec1-csv-sample "$GEN_PCAP" CSV  1 1 true  "$ALERTS"
leg t3-sec1-json       "$GEN_PCAP" JSON 3 1 false "$ALERTS"
leg t3-sec2-csv-sample "$GEN_PCAP" CSV  3 2 true  "$ALERTS"
if [ -f "$PCAP" ]; then
	leg t3-sec1-json-ua "$PCAP" JSON 3 1 false ""
else
	echo "SKIP t3-sec1-json-ua (capture not found: $PCAP)"
fi

echo "[alert-delivery] $nb_run runs, $nb_fail failed legs"
[ "$nb_fail" -eq 0 ]
