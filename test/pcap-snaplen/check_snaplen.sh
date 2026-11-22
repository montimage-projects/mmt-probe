#!/bin/sh
# Regression check for the PCAP snap-len/worker-ring overflow (issue #1).
#
# Each worker ring element is sizeof(pkthdr_t) + snap_len bytes. Before the
# fix, _got_a_packet_smp() copied caplen bytes into it unconditionally, so
# snap-len = 0 ("no limit" to libpcap) or any snap-len < caplen overflowed
# into the memory following the element.
#
# Runs the probe over two generated captures - 1500-byte and 64-byte frames -
# for each snap-len in {0, 64, 65535} and each thread-nb in {1, 2}, and
# asserts for every run that:
#   - the probe reaches the end of the capture and exits with status 0;
#   - the log shows no crash/sanitizer marker (SEGV, abort, ASan, UBSan,
#     glibc heap corruption);
#   - the total number of packets reported as processed by the workers equals
#     the number of packets in the capture, and none was dropped.
#
# On the unfixed code the 1500-B capture segfaults or corrupts the heap and
# the 64-B capture loses packets, so the check fails.
#
# Usage: check_snaplen.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the captures, config and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: PACKETS, FLOWS, THREAD_QUEUE, RUN_TIMEOUT,
#                    SNAP_LENS, THREAD_NBS.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

PACKETS=${PACKETS:-2000}
FLOWS=${FLOWS:-64}
THREAD_QUEUE=${THREAD_QUEUE:-2048}
RUN_TIMEOUT=${RUN_TIMEOUT:-120}
SNAP_LENS=${SNAP_LENS:-"0 64 65535"}
THREAD_NBS=${THREAD_NBS:-"1 2"}

#when the probe is built with sanitizers: a clean run must report nothing;
# leak reports are out of scope for this check
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
GEN=$SELF_DIR/gen_pcap.py

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-pcap-snaplen.XXXXXX")
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
command -v python3 >/dev/null || fail "python3 not found"

#--- generate the captures ----------------------------------------------
python3 "$GEN" "$WORK_DIR/big.pcap"   1500 "$PACKETS" "$FLOWS" \
	|| fail "cannot generate big.pcap"
python3 "$GEN" "$WORK_DIR/small.pcap" 64 "$PACKETS" "$FLOWS" \
	|| fail "cannot generate small.pcap"

#--- one probe run -------------------------------------------------------
nb_fail=0
nb_run=0

run_one() {
	# $1: pcap file, $2: snap-len, $3: thread-nb, $4: expected packets
	pcap=$1 snap=$2 threads=$3 expected=$4
	name=$(basename "$pcap" .pcap)-s$snap-t$threads
	log="$WORK_DIR/$name.log"
	nb_run=$((nb_run + 1))

	timeout -s KILL "$RUN_TIMEOUT" "$PROBE" -c "$CONF" -t "$pcap" \
		-X input.snap-len="$snap" -X thread-nb="$threads" \
		-X thread-queue="$THREAD_QUEUE" \
		>"$log" 2>&1
	rc=$?

	processed=$(sed -n 's/.*processed \([0-9,]*\) packets.*/\1/p' "$log" \
		| tr -d ',' | awk '{s += $1} END {print s+0}')
	dropped=$(sed -n 's/.*dropped \([0-9,]*\) packets.*/\1/p' "$log" \
		| tr -d ',' | awk '{s += $1} END {print s+0}')
	done_line=$(grep -c "reached to the end of pcap file" "$log")
	crash_lines=$(grep -icE \
		'segv|abort|sanitizer|runtime error|malloc\(\)|free\(\)|corrupt|deadly signal|unaligned tcache' \
		"$log")

	problems=""
	[ "$rc" -eq 0 ]            || problems="$problems exit=$rc"
	[ "$done_line" -ge 1 ]     || problems="$problems no-eof"
	[ "$crash_lines" -eq 0 ]   || problems="$problems crash-markers=$crash_lines"
	[ "$processed" = "$expected" ] || problems="$problems processed=$processed!=$expected"
	[ "$dropped" = "0" ]       || problems="$problems dropped=$dropped"

	if [ -z "$problems" ]; then
		echo "PASS $name ($processed/$expected packets)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log)"
	fi
}

echo "check_snaplen: probe=$PROBE packets=$PACKETS flows=$FLOWS queue=$THREAD_QUEUE"
for pcap in "$WORK_DIR/big.pcap" "$WORK_DIR/small.pcap"; do
	for snap in $SNAP_LENS; do
		for threads in $THREAD_NBS; do
			run_one "$pcap" "$snap" "$threads" "$PACKETS"
		done
	done
done

echo "check_snaplen: $((nb_run - nb_fail))/$nb_run runs passed"
[ "$nb_fail" -eq 0 ]
