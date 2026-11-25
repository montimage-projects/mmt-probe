#!/bin/sh
# Regression check for issue #39: '-X output.format=1' was refused with a
# bare "Unexpected value [1]", and -x listed output.format as a uint16_t.
# output.format takes a name, CSV or JSON, case-insensitive (an empty value
# means CSV), in the configuration file and through -X alike: both go
# through conf_parse_output_format(). A number is refused by both.
#
# Legs:
#   - every accepted spelling works in the configuration file and through
#     -X (over a configuration holding the other format), and all the
#     spellings of one format write byte-identical reports; the CSV and
#     JSON reports differ and the JSON one is JSON;
#   - an invalid value (a number, an unknown name) is refused through -X
#     with an error naming the accepted values and exit status 1, and in
#     the configuration file with the parser's error and a non-zero exit;
#   - -x lists output.format with its accepted values, -h names them;
#   - the other enum-like options reachable through -X (input.mode,
#     session-report.rtt-base, and socket-output.type and
#     security.ignore-remain-flow on the builds that have them) are
#     listed by -x with their names, accept a name through -X (the run
#     reaches the end of the pcap; whether the value takes effect is not
#     checked for them) and refuse a number with the same kind of error.
#
# '-X output.format=' (an empty value) is checked to mean CSV, as an empty
# 'format' does in the file: an empty value after '=' is applied, only a
# missing '=' warns "not well-formatted ... Ignored it" and skips the
# parameter (issue #40).
#
# On the unfixed code the refusals do not name the accepted values and -x
# prints '(uint16_t)', so the check fails.
#
# Usage: check_output_format.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the generated confs, reports and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: RUN_TIMEOUT, PCAP.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUN_TIMEOUT=${RUN_TIMEOUT:-120}

#when the probe is built with sanitizers: leak reports are out of scope
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-output-format.XXXXXX")
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
nb_skip=0

pass() { echo "  PASS $1"; }
bad()  { echo "  FAIL $1: $2"; nb_fail=$((nb_fail + 1)); }

#write the configuration of case $1 with 'format = $2', reporting into
# $WORK_DIR/$1/out/; prints the configuration path
make_conf() {
	dir=$WORK_DIR/$1
	rm -rf "$dir"
	mkdir -p "$dir/out"
	sed -e "s|^    format       = CSV\$|    format       = $2|" \
	    -e "s|\"check.pcap\"|\"$PCAP\"|" "$CONF" > "$dir/probe.conf"
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

#run the probe for case $1 over the configuration $2; remaining arguments
# are passed to the probe. Sets $status and leaves the log in $dir/log
run_probe() {
	name=$1 conf=$2
	shift 2
	nb_run=$((nb_run + 1))
	status=0
	$TIMEOUT "$PROBE" -c "$conf" "$@" > "$WORK_DIR/$name/log" 2>&1 || status=$?
}

#a run that must process the whole pcap and write a report; the report is
# kept as $WORK_DIR/$1.report for the comparisons
expect_run() {
	# $1: case name, $2: format in the configuration file; remaining
	# arguments are passed to the probe
	name=$1
	conf=$(make_conf "$1" "$2")
	shift 2
	run_probe "$name" "$conf" "$@"
	if [ "$status" -ne 0 ]; then
		bad "$name" "exit status $status, expected 0"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	collect_reports "$name" > "$WORK_DIR/$name.report"
	if [ ! -s "$WORK_DIR/$name.report" ]; then
		bad "$name" "no report written"
		return
	fi
	pass "$name"
}

#print the reports of case $1: the file output names each file
# <timestamp>_<thread>_data.csv, so they are concatenated in thread order
# and the run-dependent timestamp is left out
collect_reports() {
	for f in "$WORK_DIR/$1/out/"*_data.csv; do
		[ -f "$f" ] || continue
		t=${f##*/}
		t=${t#*_}
		printf '%s\t%s\n' "${t%%_*}" "$f"
	done | sort -n | while IFS='	' read -r t f; do
		cat "$f"
	done
}

#a run that must be refused before any packet: exit status $2 (or any
# non-zero one when $2 is 'nonzero'), never a crash by a sanitizer, and
# the log must hold the fixed string $3
expect_reject() {
	# $1: case name, $2: expected status, $3: expected message, $4: format
	# in the configuration file; remaining arguments are passed to the probe
	name=$1 want=$2 msg=$3
	conf=$(make_conf "$1" "$4")
	shift 4
	run_probe "$name" "$conf" "$@"
	if [ "$status" -eq 0 ]; then
		bad "$name" "accepted, expected a refusal"
		return
	fi
	if [ "$want" != nonzero ] && [ "$status" -ne "$want" ]; then
		bad "$name" "exit status $status, expected $want"
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if grep -q 'Sanitizer\|runtime error' "$WORK_DIR/$name/log"; then
		bad "$name" "sanitizer report"
		return
	fi
	if ! grep -qF -- "$msg" "$WORK_DIR/$name/log"; then
		bad "$name" "missing error \"$msg\""
		sed 's/^/      /' "$WORK_DIR/$name/log" | tail -5
		return
	fi
	if [ -n "$(collect_reports "$name")" ]; then
		bad "$name" "a report was written"
		return
	fi
	pass "$name"
}

#the reports of all the cases $2... must be identical to the one of $1
expect_same() {
	ref=$1
	shift
	for c in "$@"; do
		[ -f "$WORK_DIR/$c.report" ] || continue
		if cmp -s "$WORK_DIR/$ref.report" "$WORK_DIR/$c.report"; then
			pass "same-report $c = $ref"
		else
			bad "same-report $c" "differs from $ref"
		fi
	done
}

FORMAT_VALUES="CSV or JSON, case-insensitive (empty means CSV)"

echo "[1] accepted spellings of output.format"
#the configuration file: bare names, quoted names, and the empty string
expect_run conf-CSV         CSV
expect_run conf-csv         csv
expect_run conf-Csv         Csv
expect_run conf-quoted-csv  '"csv"'
expect_run conf-empty       '""'
expect_run conf-JSON        JSON
expect_run conf-json        json
expect_run conf-Json        Json
expect_run conf-quoted-json '"JSON"'
#-X over a configuration holding the other format
expect_run X-CSV   JSON -X output.format=CSV
expect_run X-csv   JSON -X output.format=csv
expect_run X-Csv   JSON -X output.format=Csv
expect_run X-empty JSON -X output.format=
expect_run X-JSON  CSV  -X output.format=JSON
expect_run X-json  CSV  -X output.format=json
expect_run X-Json  CSV  -X output.format=Json

echo "[2] every spelling of a format writes the same report"
expect_same conf-CSV conf-csv conf-Csv conf-quoted-csv conf-empty \
	X-CSV X-csv X-Csv X-empty
expect_same conf-JSON conf-json conf-Json conf-quoted-json \
	X-JSON X-json X-Json
if [ -f "$WORK_DIR/conf-CSV.report" ] && [ -f "$WORK_DIR/conf-JSON.report" ]; then
	if cmp -s "$WORK_DIR/conf-CSV.report" "$WORK_DIR/conf-JSON.report"; then
		bad "csv-json-differ" "the CSV and JSON reports are identical"
	else
		pass "csv-json-differ"
	fi
	#a JSON report line is an array; a CSV one starts with the report id
	if head -n 1 "$WORK_DIR/conf-JSON.report" | grep -q '^\['; then
		pass "json-is-json"
	else
		bad "json-is-json" "first JSON report line: $(head -n 1 "$WORK_DIR/conf-JSON.report" | cut -c1-80)"
	fi
	if head -n 1 "$WORK_DIR/conf-CSV.report" | grep -q '^[0-9]'; then
		pass "csv-is-csv"
	else
		bad "csv-is-csv" "first CSV report line: $(head -n 1 "$WORK_DIR/conf-CSV.report" | cut -c1-80)"
	fi
fi

echo "[3] invalid values of output.format"
for v in 0 1 2 XML csvx; do
	expect_reject "X-invalid-$v" 3 \
		"Unexpected value [$v] for [output.format]: expect $FORMAT_VALUES" \
		CSV -X "output.format=$v"
done
#the configuration file refuses them too, with the parser's own error and
# the do-not-restart status 3 (issue #40: it used to die by abort(),
# status 134; issue #45: refusals now exit EXIT_STATUS_NO_RESTART)
for v in 0 1 XML; do
	expect_reject "conf-invalid-$v" 3 \
		"Invalid '$v' for option 'format'. Expect $FORMAT_VALUES." "$v"
done

echo "[4] -x and -h name the accepted values"
mkdir -p "$WORK_DIR/list"
"$PROBE" -x > "$WORK_DIR/list/x" 2>&1 || true
"$PROBE" -h > "$WORK_DIR/list/h" 2>&1 || true
nb_run=$((nb_run + 2))
if grep -qxF "output.format ($FORMAT_VALUES)" "$WORK_DIR/list/x"; then
	pass "x-output-format"
else
	bad "x-output-format" "-x prints: $(grep '^output.format ' "$WORK_DIR/list/x")"
fi
if grep -qF "output.format takes $FORMAT_VALUES" "$WORK_DIR/list/h"; then
	pass "h-output-format"
else
	bad "h-output-format" "-h does not name the values of output.format"
fi

echo "[5] the other enum-like options"
#$1: parameter, $2: its accepted values as printed, $3: an accepted name,
# $4: 'always' when every build has the parameter, else the module it needs
check_enum() {
	param=$1 values=$2 name=$3 module=$4
	if [ "$module" != always ] && ! grep -q "^$param " "$WORK_DIR/list/x"; then
		echo "  SKIP $param (no $module)"
		nb_skip=$((nb_skip + 1))
		return
	fi
	if grep -qxF "$param ($values)" "$WORK_DIR/list/x"; then
		pass "x-$param"
	else
		bad "x-$param" "-x prints: $(grep "^$param " "$WORK_DIR/list/x")"
	fi
	expect_run "X-$param-$name" CSV -X "$param=$name"
	expect_reject "X-$param-invalid" 3 \
		"Unexpected value [1] for [$param]: expect $values" \
		CSV -X "$param=1"
}
check_enum input.mode               "ONLINE or OFFLINE"               OFFLINE always
check_enum session-report.rtt-base  "SENDER, CAPTOR or PREFER_SENDER" CAPTOR  always
check_enum socket-output.type       "UNIX, TCP (alias INTERNET), UDP or BOTH" UDP SOCKET_MODULE
check_enum security.ignore-remain-flow "NONE (alias false), SECURITY (alias true) or DPI" DPI SECURITY_MODULE

echo "output-format: $nb_run runs, $nb_fail failed, $nb_skip skipped"
[ "$nb_fail" -eq 0 ] || exit 1
echo "output-format: all checks passed"
