#!/bin/sh
# Regression check for the MQTT dead channel (issue #53, review F2):
# once the broker could not be reached at start-up, mqtt_output_send()
# dropped every report silently and the channel never retried the
# connection for the rest of the run.
#
# The probe is fed test/UA-Exp01.pcap through a FIFO held open so that it
# stays alive while system-report ticks one report every 5 seconds onto
# the mqtt and stdout channels:
#
#   - run-dead-no-broker: no broker exists at all. On the fixed code the
#     log must carry a rate-limited "dropped N report(s)" warning - not
#     one line per report - and periodic "Failed to connect MQTT" retries
#     (every MQTT_RECONNECT_INTERVAL_SECONDS); the run exits cleanly.
#     On the unfixed code there is no dropped-report warning and exactly
#     one connect attempt (the one at init).
#   - run-broker-late: the probe starts with no broker, then an
#     eclipse-mosquitto container comes up a few seconds later. On the
#     fixed code the next periodic retry connects ("Connected MQTT") and
#     the following reports reach the broker, which a mosquitto_sub run
#     inside the same container proves. On the unfixed code nothing ever
#     reconnects.
#
# Both legs need a probe built with MQTT_MODULE and skip cleanly
# otherwise; the second leg additionally needs a usable docker daemon
# and skips when there is none (or SKIP_DOCKER=1).
#
# Usage: check_mqtt_dead_channel.sh [PROBE] [WORKDIR]
# Overrides via env: RUN_TIMEOUT, HOLD_SECONDS, PCAP, MQTT_IMAGE,
#                    SKIP_DOCKER, BROKER_DELAY, FREE_MIN_GB.

set -u

PROBE=${1:-./probe}
WORK_DIR=${2:-}

RUN_TIMEOUT=${RUN_TIMEOUT:-120}
#seconds the pcap feed holds the FIFO open after the capture content:
# long enough for several system-report ticks (one every 5 s), a few
# reconnect retries (every 10 s) and one drop warning interval (30 s)
HOLD_SECONDS=${HOLD_SECONDS:-45}
#seconds between the probe start and the broker container start
BROKER_DELAY=${BROKER_DELAY:-8}
#docker image of the broker leg, pinned by digest
MQTT_IMAGE=${MQTT_IMAGE:-eclipse-mosquitto@sha256:21421af7b32bf9ce508e9090c8eb13bb81f410ca778dc205506180a6f862d0eb}
SKIP_DOCKER=${SKIP_DOCKER:-0}
#the run refuses to start a container while less memory is available
FREE_MIN_GB=${FREE_MIN_GB:-8}
CONTAINER_NAME="f57m-mqtt-dead-channel-broker"
BROKER_PORT=18883
BROKER_TTL=$((HOLD_SECONDS + BROKER_DELAY + 30))

#when the probe is built with sanitizers: a clean run must report nothing;
# leak reports are out of scope for this check
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONF=$SELF_DIR/dead-channel.conf
PCAP=${PCAP:-$SELF_DIR/../UA-Exp01.pcap}

CLEAN=0
if [ -z "$WORK_DIR" ]; then
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mmt-mqtt-dead-channel.XXXXXX")
	CLEAN=1
else
	mkdir -p "$WORK_DIR"
fi
cleanup() {
	docker kill "$CONTAINER_NAME" >/dev/null 2>&1 || true
	docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
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
nb_skip=0

crashed() {
	grep -qiE 'crash signal received|Segmentation fault|runtime error|AddressSanitizer' "$1"
}

#the module list of "probe -v" does not mention MQTT (limit.h), so the
# build is probed for the module's own log string instead
if ! strings "$PROBE" 2>/dev/null | grep -q "connect MQTT to"; then
	echo "SKIP all (probe built without MQTT_MODULE)"
	exit 0
fi

echo "check_mqtt_dead_channel: probe=$PROBE conf=$CONF pcap=$PCAP"

#--- leg 1: no broker at all -------------------------------------------------
nb_run=$((nb_run + 1))
name="dead-no-broker"
dir="$WORK_DIR/$name"
mkdir -p "$dir"
fifo="$dir/in.fifo"
mkfifo "$fifo"
( cat "$PCAP"; sleep "$HOLD_SECONDS" ) > "$fifo" &
timeout -s KILL $((RUN_TIMEOUT + HOLD_SECONDS)) "$PROBE" -c "$CONF" -t "$fifo" \
	>"$dir/run.log" 2>&1
rc=$?
log="$dir/run.log"

sends=$(grep -cE '^[0-9]+,1,"' "$log" 2>/dev/null || true)
warns=$(grep -c "dropped .* report" "$log" 2>/dev/null || true)
fails=$(grep -c "Failed to connect MQTT" "$log" 2>/dev/null || true)

problems=""
[ "$rc" -eq 0 ]        || problems="$problems exit=$rc"
grep -q "reached to the end of pcap file" "$log" || problems="$problems no-eof"
crashed "$log" && problems="$problems crashed"
[ "$sends" -gt 0 ]     || problems="$problems no-stdout-report"
#one warning as soon as the first report is dropped, then at most one
# per 30-s interval: $HOLD_SECONDS of sends cannot produce more than 2
[ "$warns" -ge 1 ]     || problems="$problems no-drop-warning"
[ "$warns" -le 2 ]     || problems="$problems not-rate-limited($warns)"
#the monitor and its child each log one init attempt; the periodic
# retry must add more while the channel stays dead
[ "$fails" -ge 4 ]     || problems="$problems no-reconnect-attempts($fails)"

if [ -z "$problems" ]; then
	echo "PASS $name ($sends reports, $warns warnings, $fails connect attempts)"
else
	nb_fail=$((nb_fail + 1))
	echo "FAIL $name:$problems (log: $log)"
fi

#--- leg 2: the broker comes up after the probe ------------------------------
broker_usable=0
if [ "$SKIP_DOCKER" -eq 1 ]; then
	why="SKIP_DOCKER=1"
elif ! command -v docker >/dev/null 2>&1; then
	why="docker not installed"
elif ! docker info >/dev/null 2>&1; then
	why="docker daemon not usable"
elif [ "$(free -g | awk '/^Mem:/{print $7}')" -lt "$FREE_MIN_GB" ]; then
	why="less than ${FREE_MIN_GB}G available"
else
	broker_usable=1
fi
if [ "$broker_usable" -eq 0 ]; then
	nb_skip=$((nb_skip + 1))
	echo "SKIP run-broker-late ($why)"
fi

if [ "$broker_usable" -eq 1 ]; then
	name="broker-late"
	nb_run=$((nb_run + 1))
	dir="$WORK_DIR/$name"
	mkdir -p "$dir/mosq"
	printf 'listener 1883 0.0.0.0\nallow_anonymous true\npersistence false\n' \
		> "$dir/mosq/mosquitto.conf"
	fifo="$dir/in.fifo"
	mkfifo "$fifo"
	( cat "$PCAP"; sleep "$HOLD_SECONDS" ) > "$fifo" &
	timeout -s KILL $((RUN_TIMEOUT + HOLD_SECONDS)) "$PROBE" -c "$CONF" -t "$fifo" \
		>"$dir/run.log" 2>&1 &
	probe_pid=$!

	sleep "$BROKER_DELAY"
	#the container kills itself at BROKER_TTL so nothing is left behind
	docker run --rm -d --name "$CONTAINER_NAME" \
		--memory 4g --memory-swap 4g --pids-limit 512 \
		--user "$(id -u):$(id -g)" \
		-p "127.0.0.1:$BROKER_PORT:1883" \
		-v "$dir/mosq":/mosquitto/config:ro \
		--entrypoint timeout \
		"$MQTT_IMAGE" -s KILL "$BROKER_TTL" \
		mosquitto -c /mosquitto/config/mosquitto.conf >"$dir/docker.log" 2>&1 \
		|| echo "docker-run-failed" >> "$dir/docker.log"

	#the first report published after the reconnect proves the channel
	# works: mosquitto_sub exits 0 on its first message
	docker exec "$CONTAINER_NAME" \
		mosquitto_sub -h 127.0.0.1 -p 1883 -t "mmt-i53-dead-channel" \
		-C 1 -W "$((HOLD_SECONDS + 20))" >"$dir/sub.log" 2>&1
	sub_rc=$?

	wait "$probe_pid"; rc=$?
	log="$dir/run.log"

	connected=$(grep -c "Connected MQTT to" "$log" 2>/dev/null || true)
	received=$(grep -c . "$dir/sub.log" 2>/dev/null || true)

	problems=""
	[ "$rc" -eq 0 ]        || problems="$problems exit=$rc"
	crashed "$log" && problems="$problems crashed"
	[ "$connected" -ge 1 ] || problems="$problems never-reconnected"
	[ "$sub_rc" -eq 0 ]    || problems="$problems sub_rc=$sub_rc"
	[ "$received" -ge 1 ]  || problems="$problems no-report-delivered"

	if [ -z "$problems" ]; then
		echo "PASS $name (reconnected, report delivered)"
	else
		nb_fail=$((nb_fail + 1))
		echo "FAIL $name:$problems (log: $log, sub: $dir/sub.log, docker: $dir/docker.log)"
	fi
fi

echo "check_mqtt_dead_channel: $((nb_run - nb_fail))/$nb_run runs passed${nb_skip:+, $nb_skip skipped}"
[ "$nb_fail" -eq 0 ]
