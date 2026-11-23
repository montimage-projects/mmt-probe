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
# A third capture, hugesnap.pcap, has well-formed 64-byte frames but a
# header declaring snaplen 0x7FFFFFFF: at snap-len = 0 the effective snap
# length must stay at SNAP_CAP (262144, libpcap's maximum) so the workers'
# ring elements stay small. The run is given MEM_LIMIT_KB kilobytes of
# address space: a build that honours the declared value would need
# terabytes for the rings and aborts with "Cannot allocate FIFO" instead.
#
# On the unfixed code the 1500-B capture segfaults or corrupts the heap and
# the 64-B capture loses packets, so the check fails.
#
# Usage: check_snaplen.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the captures, config and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: PACKETS, FLOWS, THREAD_QUEUE, RUN_TIMEOUT,
#                    SNAP_LENS, THREAD_NBS, MEM_LIMIT_KB, SNAP_CAP.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

PACKETS=${PACKETS:-2000}
FLOWS=${FLOWS:-64}
THREAD_QUEUE=${THREAD_QUEUE:-2048}
RUN_TIMEOUT=${RUN_TIMEOUT:-120}
SNAP_LENS=${SNAP_LENS:-"0 64 65535"}
THREAD_NBS=${THREAD_NBS:-"1 2"}
#0x7FFFFFFF: the maximal snap length a classic pcap header can declare
HUGE_SNAP_DECLARED=${HUGE_SNAP_DECLARED:-2147483647}
#the ceiling the effective snap length is bounded by (PCAP_FILE_SNAP_LEN_MAX)
SNAP_CAP=${SNAP_CAP:-262144}
#address-space limit for the hugesnap runs: 6 GiB covers the capped
# rings (~0.5 GiB per worker at thread-queue 2048) with headroom, while
# an uncapped build needs ~4 TiB and cannot start
MEM_LIMIT_KB=${MEM_LIMIT_KB:-6291456}

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

#an ASan build itself reserves terabytes of address space: the memory
# limit is skipped there, the effective snap length is still checked
if [ "$MEM_LIMIT_KB" -gt 0 ] && ldd "$PROBE" 2>/dev/null | grep -qi 'asan'; then
	MEM_LIMIT_KB=0
fi

#--- generate the captures ----------------------------------------------
python3 "$GEN" "$WORK_DIR/big.pcap"   1500 "$PACKETS" "$FLOWS" \
	|| fail "cannot generate big.pcap"
python3 "$GEN" "$WORK_DIR/small.pcap" 64 "$PACKETS" "$FLOWS" \
	|| fail "cannot generate small.pcap"
python3 "$GEN" "$WORK_DIR/hugesnap.pcap" 64 "$PACKETS" "$FLOWS" "$HUGE_SNAP_DECLARED" \
	|| fail "cannot generate hugesnap.pcap"

#--- one probe run -------------------------------------------------------
nb_fail=0
nb_run=0

run_one() {
	# $1: pcap file, $2: snap-len, $3: thread-nb, $4: expected packets
	# $5: address-space limit in KiB (0: none), $6: maximal snap length the
	#     run may report (0: not checked)
	pcap=$1 snap=$2 threads=$3 expected=$4
	mem_kb=${5:-0} max_snap=${6:-0}
	name=$(basename "$pcap" .pcap)-s$snap-t$threads
	log="$WORK_DIR/$name.log"
	nb_run=$((nb_run + 1))

	if [ "$mem_kb" -gt 0 ]; then
		( ulimit -v "$mem_kb" || exit 1
		  exec timeout -s KILL "$RUN_TIMEOUT" "$PROBE" -c "$CONF" -t "$pcap" \
			-X input.snap-len="$snap" -X thread-nb="$threads" \
			-X thread-queue="$THREAD_QUEUE" \
		) >"$log" 2>&1
	else
		timeout -s KILL "$RUN_TIMEOUT" "$PROBE" -c "$CONF" -t "$pcap" \
			-X input.snap-len="$snap" -X thread-nb="$threads" \
			-X thread-queue="$THREAD_QUEUE" \
			>"$log" 2>&1
	fi
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
	if [ "$max_snap" -gt 0 ]; then
		used=$(sed -n 's/.*[Ss]nap length \([0-9][0-9]*\).*/\1/p' "$log" | head -n 1)
		{ [ -n "$used" ] && [ "$used" -le "$max_snap" ]; } \
			|| problems="$problems snaplen=${used:-not-logged}>$max_snap"
	fi

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
#the header-declared snap length is untrusted: at snap-len = 0 the
# effective snap length must be capped at SNAP_CAP and the rings must
# stay inside MEM_LIMIT_KB of address space
for threads in $THREAD_NBS; do
	run_one "$WORK_DIR/hugesnap.pcap" 0 "$threads" "$PACKETS" "$MEM_LIMIT_KB" "$SNAP_CAP"
done

echo "check_snaplen: $((nb_run - nb_fail))/$nb_run runs passed"
[ "$nb_fail" -eq 0 ]
