#!/bin/sh
# Regression check for the file-output crash of review note N3 (PR #35):
# an enabled file output with 'output-file' unset made file_output_alloc_init
# pass NULL to strlen() and die by SIGSEGV before any packet was read.
#
# Every path that leaves a file/dir/descriptor option unset must now be
# rejected at start-up by conf_validate() with an error naming the
# 'section.key' option and a non-zero exit, never a crash. Legs:
#   - file-output.output-file / file-output.output-dir missing or empty,
#     via the configuration file and via -X overrides;
#   - behaviour.output-file missing (the other file_output consumer);
#   - dynamic-config.descriptor missing (only on a DYNAMIC_CONFIG_MODULE
#     build), dump-pcap.output-dir, socket-output.descriptor and
#     reconstruct-data.*.output-dir (only on the matching module builds);
#   - a disabled file-output needs no output-file (no false reject);
#   - a fully configured file-output still runs to the end of the pcap,
#     and so does one enabled only by -X overrides;
#   - a configuration without the 'reconstruct-data http' and/or 'ftp'
#     block runs (their init dereferenced the NULL block), and a -X on a
#     missing block is rejected instead of writing through NULL.
#
# On the unfixed code these legs die by SIGSEGV (or a UBSan report), or
# run without printing the error, so the check fails.
#
# Usage: check_file_output_unset.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the generated confs and logs
#            (default: a new mktemp -d, removed on exit)
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
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-file-output-unset.XXXXXX")
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
[ -f "$PCAP" ]  || fail "pcap file not found: $PCAP"

OUT_DIR=$WORK_DIR/out
mkdir -p "$OUT_DIR"

nb_fail=0
nb_run=0
nb_skip=0

#a run that must be rejected: exit status 1 - a refused configuration
# exits cleanly, never the 134 of the old abort() - print an error naming
# the required 'section.key' option, and never crash nor process packets
expect_reject() {
	# $1: case name, $2: the 'section.key' the error must name;
	# remaining arguments are passed to the probe
	name="reject-$1" key=$2
	shift 2
	log="$WORK_DIR/$name.log"
	nb_run=$((nb_run + 1))

	timeout -s KILL "$RUN_TIMEOUT" "$PROBE" "$@" >"$log" 2>&1
	rc=$?

	problems=""
	[ "$rc" -eq 3 ] || problems="$problems exit=$rc"
	grep -qF "$key" "$log"   || problems="$problems no-error-for-$key"
	grep -q "reached to the end of pcap file" "$log" \
		&& problems="$problems ran-anyway"
	if grep -qiE 'crash signal received|Segmentation fault|runtime error|AddressSanitizer' "$log"; then
		problems="$problems crashed"
	fi

	if [ -z "$problems" ]; then
		echo "PASS $name (rejected, exit=$rc)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log)"
	fi
}

#a run that must succeed end to end: exit 0, reach the end of the pcap, and
# neither crash nor report a missing-option error
expect_run() {
	name="run-$1"
	shift
	log="$WORK_DIR/$name.log"
	nb_run=$((nb_run + 1))

	timeout -s KILL "$RUN_TIMEOUT" "$PROBE" "$@" >"$log" 2>&1
	rc=$?

	problems=""
	[ "$rc" -eq 0 ]        || problems="$problems exit=$rc"
	grep -q "reached to the end of pcap file" "$log" \
		|| problems="$problems no-eof"
	grep -q "requires .* to be set" "$log" \
		&& problems="$problems unexpected-reject"
	if grep -qiE 'crash signal received|Segmentation fault|runtime error|AddressSanitizer' "$log"; then
		problems="$problems crashed"
	fi

	if [ -z "$problems" ]; then
		echo "PASS $name"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log)"
	fi
}

conf_with() {
	# $1: output file name, $2: the conf to extend (or - for $CONF);
	# the remaining arguments are appended as configuration blocks: an
	# appended non-multi block (file-output, ...) is merged by libconfuse
	# with an earlier one, its options winning
	out="$WORK_DIR/$1"
	shift
	if [ "$1" = "-" ]; then
		cp "$CONF" "$out"
	else
		cp "$1" "$out"
	fi
	shift
	for block in "$@"; do
		printf '%s\n' "$block" >> "$out"
	done
	printf '%s\n' "$out"
}

#the modules compiled in, for the module-only legs
MODULES=$("$PROBE" -v 2>&1)
has() {
	printf '%s\n' "$MODULES" | grep -q "$1"
}
skip() {
	nb_skip=$((nb_skip + 1))
	echo "SKIP $1 (no $2)"
}

echo "check_file_output_unset: probe=$PROBE pcap=$PCAP"

#file-output: the reported crash site - output-file unset crashes in
# strlen() when the report file name is built
expect_reject "file-output-file" "file-output.output-file" \
	-c "$(conf_with nofile.conf - \
		'file-output { enable = true output-dir = "'"$OUT_DIR"'" }')" \
	-t "$PCAP"

#output-dir unset reaches the same strlen() through __ARR(directory)
expect_reject "file-output-dir" "file-output.output-dir" \
	-c "$(conf_with nodir.conf - \
		'file-output { enable = true output-file = "data.csv" }')" \
	-t "$PCAP"

#an empty output-dir is a missing value, not a directory
expect_reject "file-output-empty-dir" "file-output.output-dir" \
	-c "$(conf_with emptydir.conf - \
		'file-output { enable = true output-dir = "" output-file = "data.csv" }')" \
	-t "$PCAP"

#the -X override path enables the block after parsing: the filename stays
# NULL and the same validation must reject it
expect_reject "file-output-x-enable" "file-output.output-file" \
	-c "$CONF" -X file-output.enable=true -t "$PCAP"

#an empty value given via -X is missing the same way
expect_reject "file-output-x-empty" "file-output.output-file" \
	-c "$CONF" -X file-output.enable=true -X file-output.output-file= \
	-t "$PCAP"

#behaviour is the other file_output consumer (dpi.c:217): same
# requirement; session-report is enabled as behaviour.enable requires it
sed '/session-report {/,/}/ s/enable = false/enable = true/' \
	"$CONF" > "$WORK_DIR/session-on.conf"
expect_reject "behaviour-file" "behaviour.output-file" \
	-c "$(conf_with behaviour.conf "$WORK_DIR/session-on.conf" \
		'behaviour { enable = true output-dir = "'"$OUT_DIR"'" }')" \
	-t "$PCAP"

#dynamic-config: the descriptor is a UNIX socket path, strlen()ed at
# server start - only checkable when the module was compiled in
if has DYNAMIC_CONF; then
	expect_reject "dynamic-config" "dynamic-config.descriptor" \
		-c "$(conf_with dynconf.conf - 'dynamic-config { enable = true }')" \
		-t "$PCAP"
else
	skip dynamic-config DYNAMIC_CONFIG_MODULE
fi

#dump-pcap: output-dir builds the dump file names
if has PCAP_DUMP; then
	expect_reject "dump-pcap" "dump-pcap.output-dir" \
		-c "$(conf_with dumppcap.conf - 'dump-pcap { enable = true }')" \
		-t "$PCAP"
else
	skip dump-pcap PCAP_DUMP_MODULE
fi

#socket-output: the descriptor is a UNIX socket path strcpy()ed into
# sun_path, and the hostname is resolved - both required when their socket
# type is in use
if has SOCKET; then
	expect_reject "socket-descriptor" "socket-output.descriptor" \
		-c "$(conf_with sockunix.conf - \
			'socket-output { enable = true type = UNIX descriptor = "" }')" \
		-t "$PCAP"
	expect_reject "socket-hostname" "socket-output.hostname" \
		-c "$(conf_with sockinet.conf - \
			'socket-output { enable = true type = TCP hostname = "" }')" \
		-t "$PCAP"
else
	skip socket-output SOCKET_MODULE
fi

#reconstruct-data: output-dir builds the reconstructed file names; the
# fixture's disabled blocks are flipped to enabled, and tcp reassembly (with
# the ip defragmentation it needs) is required by the reconstruction itself;
# its option exists only on a TCP_REASSEMBLY_MODULE build
REASSEMBLY=""
has TCP_REASSEMBLY \
	&& REASSEMBLY="-X enable-tcp-reassembly=true -X enable-ip-defragmentation=true"
for p in ftp http; do
	P=$(echo "$p" | tr a-z A-Z)
	if has "${P}_RECONSTRUCT"; then
		sed "/reconstruct-data $p {/,/}/ s/enable = false/enable = true/" \
			"$CONF" > "$WORK_DIR/$p.conf"
		# shellcheck disable=SC2086
		expect_reject "reconstruct-$p" "reconstruct-data.$p.output-dir" \
			-c "$WORK_DIR/$p.conf" $REASSEMBLY -t "$PCAP"
		#a -X on a block the conf left out has no field to write to
		sed "/^reconstruct-data $p {/,/^}/d" "$CONF" > "$WORK_DIR/no-$p.conf"
		expect_reject "reconstruct-$p-x-no-block" "reconstruct-data $p" \
			-c "$WORK_DIR/no-$p.conf" \
			-X "reconstruct-data.$p.output-dir=$OUT_DIR" -t "$PCAP"
		#the error names the missing block; a generic "Unexpected parameter
		# value" on top of it would wrongly blame the value (issue #40)
		nb_run=$((nb_run + 1))
		if grep -q "Unexpected parameter value" \
				"$WORK_DIR/reject-reconstruct-$p-x-no-block.log"; then
			nb_fail=$((nb_fail + 1))
			echo "FAIL reconstruct-$p-x-no-block-msg: misleading 'Unexpected parameter value' line"
		else
			echo "PASS reconstruct-$p-x-no-block-msg"
		fi
	else
		skip "reconstruct-$p" "${P}_RECONSTRUCT_MODULE"
	fi
done

#reconstruct-data is a titled multi block: leaving out the http or the ftp
# block (or both) leaves its configuration NULL, and the reconstruction init
# of a module build must take it as disabled; the remaining block is
# enabled so its init runs with a real configuration
sed -e '/^reconstruct-data http {/,/^}/d' \
	-e '/reconstruct-data ftp {/,/}/ s|enable = false|enable = true output-dir = "'"$OUT_DIR"'"|' \
	"$CONF" > "$WORK_DIR/no-http.conf"
sed -e '/^reconstruct-data ftp {/,/^}/d' \
	-e '/reconstruct-data http {/,/}/ s|enable = false|enable = true output-dir = "'"$OUT_DIR"'"|' \
	"$CONF" > "$WORK_DIR/no-ftp.conf"
sed '/^reconstruct-data [a-z]* {/,/^}/d' "$CONF" > "$WORK_DIR/no-reconstruct.conf"
for c in no-http no-ftp no-reconstruct; do
	# shellcheck disable=SC2086
	expect_run "$c" -c "$WORK_DIR/$c.conf" $REASSEMBLY -t "$PCAP"
done

#a disabled file-output needs neither option: the run must not be rejected
expect_run "disabled" \
	-c "$(conf_with disabled.conf - 'file-output { enable = false }')" \
	-t "$PCAP"

#and a fully configured file output still works to the end of the pcap;
# session-report is enabled so a report is really written
expect_run "valid" \
	-c "$(conf_with valid.conf "$WORK_DIR/session-on.conf" \
		'file-output { enable = true output-dir = "'"$OUT_DIR"'" output-file = "data.csv" }')" \
	-t "$PCAP"

#its report file is really written under output-dir
expect_file() {
	nb_run=$((nb_run + 1))
	if ls "$1"/*"$2" >/dev/null 2>&1; then
		echo "PASS $3"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $3 (no report file $2 in $1)"
	fi
}
expect_file "$OUT_DIR" data.csv output-file-created

#outputs enabled only by -X: the global output flag was computed at parse
# time, so no output was created and the first report crashed on it; a -X
# output-dir is taken as is (no '/' is appended), hence the trailing '/'
X_DIR=$WORK_DIR/x-out
mkdir -p "$X_DIR"
expect_run "x-enabled-output" -c "$CONF" \
	-X file-output.enable=true -X file-output.output-file=x.csv \
	-X file-output.output-dir="$X_DIR/" -X session-report.enable=true \
	-t "$PCAP"
expect_file "$X_DIR" x.csv x-output-file-created

#-X with no '=' warns "not well-formatted" and skips the parameter
# (issue #40): the conf value stands and the run is clean. On the unfixed
# code the warning lied - the empty "value" was applied and then refused,
# so the run exits 1 instead.
expect_run "x-no-equals" -c "$CONF" -X input.mode -t "$PCAP"
nb_run=$((nb_run + 1))
if grep -q "not well-formatted" "$WORK_DIR/run-x-no-equals.log"; then
	echo "PASS x-no-equals-warn"
else
	nb_fail=$((nb_fail + 1))
	echo "FAIL x-no-equals-warn: no 'not well-formatted' warning"
fi

echo "check_file_output_unset: $((nb_run - nb_fail))/$nb_run runs passed${nb_skip:+, $nb_skip skipped}"
[ "$nb_fail" -eq 0 ]
