#!/bin/sh
# Regression check for the PCAP snap-len/worker-ring overflow (issue #1)
# and for the input.snap-len value handling (issue #5).
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
# input.snap-len is a uint32_t bounded by PCAP_FILE_SNAP_LEN_MAX (issue #5):
#   - configured values of 65536 and 262144 must be taken as-is instead of
#     wrapping into uint16_t: on hugesnap.pcap a wrapped 65536 becomes 0
#     and resolves to the file's capped 262144, so the exact effective
#     value is asserted;
#   - out-of-range (262145), negative (-1) and non-numeric (abc) values
#     must be rejected with a clear error and the do-not-restart status
#     3, both via the -X override and via the configuration file;
#   - the same bound applies to dump-pcap.snap-len (issue #53): a bad
#     value is refused with the do-not-restart status 3, and on an ASan
#     build the refusal path must not leave allocated members behind -
#     each expect_reject run goes out under detect_leaks=1 and a
#     LeakSanitizer report counts as a failure;
#   - online, the configured value must reach pcap_set_snaplen: a live
#     capture on ONLINE_IFACE (default: lo) must log the configured value.
#     Skipped when no interface can capture (e.g. no AF_PACKET capability
#     in the container); set ONLINE_IFACE=none to skip explicitly.
#
# On the unfixed code the 1500-B capture segfaults or corrupts the heap and
# the 64-B capture loses packets, so the check fails.
#
# Usage: check_snaplen.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the captures, config and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: PACKETS, FLOWS, THREAD_QUEUE, RUN_TIMEOUT,
#                    SNAP_LENS, THREAD_NBS, MEM_LIMIT_KB, SNAP_CAP,
#                    HUGE_SNAP_DECLARED, ONLINE_IFACE, ONLINE_RUN_SECONDS.

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
#interface for the live-capture cases: "auto" tries lo then any,
# "none" skips them, any other value is used as the interface name
ONLINE_IFACE=${ONLINE_IFACE:-auto}
#seconds each live capture is left running before it gets SIGINT: enough to
# pass pcap_activate and prove the configured snap-len was accepted
ONLINE_RUN_SECONDS=${ONLINE_RUN_SECONDS:-5}

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
nb_skip=0

crash_markers() {
	grep -icE \
		'segv|abort|sanitizer|runtime error|malloc\(\)|free\(\)|corrupt|deadly signal|unaligned tcache' \
		"$1"
}

run_one() {
	# $1: pcap file, $2: snap-len, $3: thread-nb, $4: expected packets
	# $5: address-space limit in KiB (0: none), $6: maximal snap length the
	#     run may report (0: not checked), $7: exact snap length the run
	#     must report (0: not checked)
	pcap=$1 snap=$2 threads=$3 expected=$4
	mem_kb=${5:-0} max_snap=${6:-0} exact_snap=${7:-0}
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
	crash_lines=$(crash_markers "$log")

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
	if [ "$exact_snap" -gt 0 ]; then
		used=$(sed -n 's/.*[Ss]nap length \([0-9][0-9]*\).*/\1/p' "$log" | head -n 1)
		[ "$used" = "$exact_snap" ] \
			|| problems="$problems snaplen=${used:-not-logged}!=$exact_snap"
	fi

	if [ -z "$problems" ]; then
		echo "PASS $name ($processed/$expected packets)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log)"
	fi
}

expect_reject() {
	# $1: case name; $2: the option key the error message must name; the
	# remaining arguments are passed to the probe. A refused value must
	# give a clear error naming the option and its bound, the
	# do-not-restart status 3 - a refused configuration no longer dies by
	# abort(), status 134, nor exits 1 (issues #40, #45) - and no capture
	# run. The run always goes out under detect_leaks=1: a LeakSanitizer
	# report on an ASan build means the refusal path left allocated
	# members behind.
	name="reject-$1" key="$2"
	shift 2
	log="$WORK_DIR/$name.log"
	nb_run=$((nb_run + 1))

	ASAN_OPTIONS=detect_leaks=1 \
	timeout -s KILL "$RUN_TIMEOUT" "$PROBE" "$@" >"$log" 2>&1
	rc=$?

	problems=""
	[ "$rc" -eq 3 ] || problems="$problems exit=$rc"
	grep -q "$key" "$log"         || problems="$problems no-error-message"
	grep -q "$SNAP_CAP" "$log"    || problems="$problems no-bound-in-message"
	grep -q "reached to the end of pcap file" "$log" \
		&& problems="$problems ran-anyway"
	grep -qiE 'LeakSanitizer|detected memory leaks' "$log" \
		&& problems="$problems leaked"

	if [ -z "$problems" ]; then
		echo "PASS $name (rejected, exit=$rc)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log)"
	fi
}

#--- live capture ---------------------------------------------------------
if [ "$ONLINE_IFACE" = "auto" ]; then
	ONLINE_IFACES="lo any"
elif [ "$ONLINE_IFACE" = "none" ]; then
	ONLINE_IFACES=
else
	ONLINE_IFACES=$ONLINE_IFACE
fi

online_one() {
	# $1: snap-len, $2: the value the run must pass to pcap_set_snaplen.
	# A live capture proves the configured value is used as-is: the
	# "Set snap-len for pcap capture: N" line is logged right before
	# pcap_set_snaplen and pcap_activate must succeed.
	# In online mode the probe forks a capture child supervised by the main
	# process; the main process ignores SIGINT/SIGTERM while the child shuts
	# down cleanly on them. setsid puts the whole tree in its own process
	# group so SIGINT reaches both: the capture ends gracefully and the
	# supervisor exits 0.
	snap=$1 expect=$2
	usable=0
	log=
	rc=
	for iface in $ONLINE_IFACES; do
		name="online-$iface-s$snap"
		log="$WORK_DIR/$name.log"
		setsid "$PROBE" -c "$CONF" -i "$iface" \
			-X input.snap-len="$snap" -X thread-nb=0 >"$log" 2>&1 &
		pid=$!
		sleep "$ONLINE_RUN_SECONDS"
		kill -INT -"$pid" 2>/dev/null
		wait "$pid"
		rc=$?
		if grep -qiE "couldn't open device|cannot activate pcap" "$log"; then
			log=
		else
			usable=1
			break
		fi
	done

	if [ "$usable" -eq 0 ]; then
		nb_skip=$((nb_skip + 1))
		echo "SKIP online-s$snap (no interface can capture${log:+"; log: $log"})"
		return
	fi

	nb_run=$((nb_run + 1))
	got=$(sed -n 's/.*Set snap-len for pcap capture: \([0-9][0-9]*\).*/\1/p' "$log" | head -n 1)
	crash_lines=$(crash_markers "$log")

	problems=""
	[ "$rc" -eq 0 ]          || problems="$problems exit=$rc"
	[ "$got" = "$expect" ]   || problems="$problems pcap_snaplen=${got:-not-logged}!=$expect"
	[ "$crash_lines" -eq 0 ] || problems="$problems crash-markers=$crash_lines"

	if [ -z "$problems" ]; then
		echo "PASS online-s$snap (pcap snaplen $got)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL online-s$snap:$problems (log: $log)"
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

#input.snap-len is a uint32_t bounded by SNAP_CAP: configured values of
# 65536 and 262144 must be taken as-is, never wrapped into uint16_t. On
# hugesnap.pcap the declared value exceeds both, so the effective snap
# length is exactly the configured one
for threads in $THREAD_NBS; do
	run_one "$WORK_DIR/hugesnap.pcap" 65536 "$threads" "$PACKETS" "$MEM_LIMIT_KB" "$SNAP_CAP" 65536
	#s262144 also passes on the base build: a 262144 -> 0 wrap resolves to
	# the file's capped 262144, so s65536 above is the real no-wrap check
	run_one "$WORK_DIR/hugesnap.pcap" "$SNAP_CAP" "$threads" "$PACKETS" "$MEM_LIMIT_KB" "$SNAP_CAP" "$SNAP_CAP"
done

#out-of-range, negative and non-numeric values must be rejected with a
# clear error and the do-not-restart status 3, never silently wrapped
# into the field
for bad in 262145 -1 abc 4294967296; do
	expect_reject "s$bad" input.snap-len -c "$CONF" -t "$WORK_DIR/small.pcap" \
		-X input.snap-len="$bad" -X thread-nb=1
done
#the configuration file is checked the same way
sed 's/snap-len.*/snap-len = 262145/' "$CONF" > "$WORK_DIR/bad-snaplen.conf"
expect_reject "conf-file" input.snap-len -c "$WORK_DIR/bad-snaplen.conf" -t "$WORK_DIR/small.pcap"

#dump-pcap.snap-len is bound by the same PCAP_FILE_SNAP_LEN_MAX (issue
# #53): the refusal happens while parsing the configuration file block
# (the -X override rejects the value earlier, without reaching the
# leaky branch), so the block is appended to the test configuration.
# output-dir is set so the leaked member is really allocated and the
# detect_leaks=1 leg flags it on an ASan build
for bad in 262145 -1; do
	sed 's/snap-len.*/snap-len = 0/' "$CONF" > "$WORK_DIR/bad-dump-snaplen.conf"
	cat >> "$WORK_DIR/bad-dump-snaplen.conf" <<-EOF
	dump-pcap {
	    enable     = false
	    output-dir = "$WORK_DIR/dump"
	    protocols  = {"unknown"}
	    snap-len   = $bad
	}
	EOF
	expect_reject "dump-s$bad" dump-pcap.snap-len -c "$WORK_DIR/bad-dump-snaplen.conf" -t "$WORK_DIR/small.pcap"
done

#online: a configured value up to 262144 must reach pcap_set_snaplen, and
# snap-len = 0 keeps meaning PCAP_SNAP_LEN_MAX (65535)
online_one "$SNAP_CAP" "$SNAP_CAP"
online_one 0 65535

echo "check_snaplen: $((nb_run - nb_fail))/$nb_run runs passed${nb_skip:+, $nb_skip skipped}"
[ "$nb_fail" -eq 0 ]
