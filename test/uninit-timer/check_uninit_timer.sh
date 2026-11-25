#!/bin/sh
# Regression check for the uninitialised `now` on the offline timer path
# (issue #46).
#
# In _worker_thread (src/modules/packet_capture/pcap/pcap_capture.c) the
# empty-ring branch called worker_update_timer(&now) unconditionally; only
# the online branch set `now` (gettimeofday), so a worker whose ring was
# empty before its first packet - or that never received a packet at all -
# fed an uninitialised struct timeval to ms_timer_set_time and
# dpi_update_timer.
#
# Runs the probe under valgrind memcheck with --track-origins=yes on a
# generated capture whose packets all share one 5-tuple: the SMP hash sends
# them to a single worker, so with thread-nb = 3 the two other workers spin
# on their empty rings for the whole capture and, on the unfixed code,
# produce uninitialised-value reports inside worker_update_timer and
# dpi_update_timer. A small thread-queue keeps the reader blocked on the
# full ring so the empty-ring workers are scheduled while their ring is
# still empty. A second leg runs test/UA-Exp01.pcap the same way.
#
# On the fixed code, offline workers never feed the timers until a first
# packet set `now`, so both legs must show no uninitialised-value report
# and the probe must reach the end of the capture with status 0.
# Skipped when valgrind is not installed.
#
# Usage: check_uninit_timer.sh [PROBE] [WORKDIR]
#   PROBE    probe binary (default: ./probe)
#   WORKDIR  scratch dir for the capture, config and logs
#            (default: a new mktemp -d, removed on exit)
# Overrides via env: PACKETS, FRAME_BYTES, RUN_TIMEOUT, THREAD_NBS,
#                    THREAD_QUEUE, VALGRIND.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

PACKETS=${PACKETS:-5000}
FRAME_BYTES=${FRAME_BYTES:-200}
RUN_TIMEOUT=${RUN_TIMEOUT:-300}
THREAD_NBS=${THREAD_NBS:-"3"}
THREAD_QUEUE=${THREAD_QUEUE:-64}
VALGRIND=${VALGRIND:-valgrind}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/probe.conf
GEN=$SELF_DIR/gen_oneflow_pcap.py
UA_PCAP=$SELF_DIR/../UA-Exp01.pcap

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-uninit-timer.XXXXXX")
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
if ! command -v "$VALGRIND" >/dev/null; then
	echo "SKIP uninit-timer (valgrind not found)"
	exit 0
fi

#--- generate the single-flow capture -----------------------------------
python3 "$GEN" "$WORK_DIR/oneflow.pcap" "$FRAME_BYTES" "$PACKETS" \
	|| fail "cannot generate oneflow.pcap"

nb_fail=0
nb_run=0

run_one() {
	# $1: pcap file, $2: thread-nb
	pcap=$1 threads=$2
	name=$(basename "$pcap" .pcap)-t$threads
	log="$WORK_DIR/$name.log"
	vglog="$WORK_DIR/$name.valgrind"
	nb_run=$((nb_run + 1))

	#leak checking is out of scope for this check; --track-origins=yes
	# names the stack slot the uninitialised value comes from
	timeout -s KILL "$RUN_TIMEOUT" "$VALGRIND" \
		--tool=memcheck --track-origins=yes --leak-check=no \
		--log-file="$vglog" \
		"$PROBE" -c "$CONF" -t "$pcap" \
		-X thread-nb="$threads" -X thread-queue="$THREAD_QUEUE" \
		>"$log" 2>&1
	rc=$?

	problems=""
	[ "$rc" -eq 0 ] || problems="$problems exit=$rc"
	grep -q "reached to the end of pcap file" "$log" \
		|| problems="$problems no-eof"

	#any uninitialised-value report: a read that reached a conditional or
	# an address; on the unfixed code they appear in worker_update_timer
	# and dpi_update_timer, created by the `now` stack slot of _worker_thread
	uninit=$(grep -c "uninitialised" "$vglog")
	[ "$uninit" -eq 0 ] || problems="$problems uninit-reports=$uninit"

	if [ -n "$problems" ]; then
		echo "FAIL $name:$problems"
		grep -B2 -A12 "uninitialised" "$vglog" | head -40
		nb_fail=$((nb_fail + 1))
	else
		echo "PASS $name"
	fi
}

for t in $THREAD_NBS; do
	run_one "$WORK_DIR/oneflow.pcap" "$t"
	[ -f "$UA_PCAP" ] && run_one "$UA_PCAP" "$t"
done

if [ "$nb_fail" -gt 0 ]; then
	echo "FAIL uninit-timer: $nb_fail/$nb_run run(s) reported uninitialised reads"
	exit 1
fi
echo "PASS uninit-timer ($nb_run runs)"
exit 0
