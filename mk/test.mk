#####################################################
# UNIT TESTS                                        #
#####################################################

# Unit check of the STIX 2.1 alert builder (src/modules/output_format/stix_format.c).
# Needs only gcc and libuuid (package uuid-dev), not MMT-DPI.
#   make test-stix
STIX_TEST_DIR := $(TOP_DIR)/test/stix_format
STIX_TEST_BIN := $(STIX_TEST_DIR)/test_stix_format

.PHONY: test-stix
test-stix:
	@echo "[COMPILE] $(notdir $(STIX_TEST_BIN))"
	$(QUIET) $(CC) -Wall -Wextra -O1 -o $(STIX_TEST_BIN) \
		$(STIX_TEST_DIR)/test_stix_format.c $(SRC_DIR)/modules/output_format/stix_format.c -luuid
	@echo "[TEST] $(notdir $(STIX_TEST_BIN))"
	$(QUIET) $(STIX_TEST_BIN)

# STIX-on variant of the report-overflow driver (issue #9): the same test
# built with -DSTIX_FORMAT and linked with the real stix_format.c, so the
# STIX path of output_write_report runs end to end — fitting bundles through
# the JSON wrap, oversized ones and non-alert bodies through the bounded CSV
# fallback. Skipped cleanly when the libuuid headers are missing, as
# test-stix needs them too.
STIX_OVERFLOW_TEST_DIR    := $(TOP_DIR)/test/report-overflow
STIX_OVERFLOW_TEST_OBJDIR := $(STIX_OVERFLOW_TEST_DIR)/obj-asan-stix
STIX_OVERFLOW_TEST_BIN    := $(STIX_OVERFLOW_TEST_DIR)/report-overflow-stix-test
STIX_OVERFLOW_TEST_OBJS   := $(STIX_OVERFLOW_TEST_OBJDIR)/report_overflow_test.o \
	$(STIX_OVERFLOW_TEST_OBJDIR)/stix_format.o
HAVE_UUID_HEADERS         := $(shell printf '#include <uuid/uuid.h>\n' | \
	$(CC) -fsyntax-only -x c - > /dev/null 2>&1 && echo 1)

$(STIX_OVERFLOW_TEST_OBJDIR)/report_overflow_test.o: $(STIX_OVERFLOW_TEST_DIR)/report_overflow_test.c
	@mkdir -p $(STIX_OVERFLOW_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -fsanitize=address -DSTIX_FORMAT -DREPORT_OVERFLOW_TEST_STIX -c -o $@ $<

$(STIX_OVERFLOW_TEST_OBJDIR)/stix_format.o: $(SRC_DIR)/modules/output_format/stix_format.c
	@mkdir -p $(STIX_OVERFLOW_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -fsanitize=address -c -o $@ $<

$(STIX_OVERFLOW_TEST_BIN): $(STIX_OVERFLOW_TEST_OBJS)
	$(QUIET) $(CC) $(CLDFLAGS) -fsanitize=address -o $@ $^ $(LIBS) -luuid

.PHONY: test-report-overflow-stix
ifdef HAVE_UUID_HEADERS
test-report-overflow-stix: --check-dpi-folder $(STIX_OVERFLOW_TEST_BIN)
	@echo "[TEST] report-overflow STIX-on under ASan"
	$(QUIET) status=0; $(STIX_OVERFLOW_TEST_BIN) || status=$$?; \
		$(RM) $(STIX_OVERFLOW_TEST_OBJDIR) $(STIX_OVERFLOW_TEST_BIN); exit $$status
else
test-report-overflow-stix:
	@echo "[TEST] report-overflow STIX-on under ASan"
	@echo "SKIP report-overflow-stix (uuid/uuid.h not found)"
endif

#####################################################
# INTEGRATION CHECKS                                #
#####################################################

# Integration check of the PCAP snap-len/worker-ring sizing (issue #1) and
# of the input.snap-len value handling (issue #5).
# Runs ./probe over generated captures (1500-B and 64-B frames, plus one
# declaring a snap length of 0x7FFFFFFF) for each snap-len in {0, 64, 65535}
# and each thread-nb in {1, 2}, asserting every packet is processed, no run
# crashes, and the file-declared snap length cannot grow the rings past
# 262144. Configured values of 65536 and 262144 must be taken as-is rather
# than wrapped, out-of-range and malformed values must be rejected with a
# clear error and a non-zero exit, and a live capture (default interface:
# lo) must reach pcap_set_snaplen with the configured value. Needs a built
# probe and python3; the captures are written under a temporary directory.
SNAPLEN_TEST_DIR := $(TOP_DIR)/test/pcap-snaplen

.PHONY: test-snaplen
test-snaplen: compile
	$(QUIET) $(SNAPLEN_TEST_DIR)/check_snaplen.sh $(TOP_DIR)/$(APP)

# The same check over an ASan build: the unfixed overflow is reported at
# the memcpy in _got_a_packet_smp. UBSan is not enabled here: it reports
# pre-existing misaligned loads in _get_packet_hash_number (pcap_capture.c).
# All objects are rebuilt and removed afterwards so a following normal
# build does not reuse sanitized objects.
.PHONY: test-snaplen-asan
test-snaplen-asan: clean
	$(QUIET) $(MAKE) compile APP=probe-asan \
		EXTRA_CFLAGS="-fsanitize=address" \
		EXTRA_LDFLAGS="-fsanitize=address"
	$(QUIET) status=0; $(SNAPLEN_TEST_DIR)/check_snaplen.sh $(TOP_DIR)/probe-asan || status=$$?; \
		$(MAKE) -s clean; $(RM) $(TOP_DIR)/probe-asan; exit $$status

# Exit-status regression (issue #2): an offline crash must die by the
# signal (a shell reports 128+signum), clean shutdowns (end of pcap,
# SIGINT, SIGTERM) must exit 0. The compile prerequisite keeps a
# parallel `make -j test` on a clean tree from racing the build.
.PHONY: test-crash
test-crash: compile
	@echo "[TEST] crash exit status"
	$(QUIET) sh $(TOP_DIR)/test/crash_exit_status.sh

# Report-writer bounds (issue #9): the writers must truncate a report that is
# longer than the buffer instead of writing past it. The driver is built with
# ASan and its objects live under test/report-overflow/ so a parallel
# `make -j test` does not race the normal build in src/.
REPORT_OVERFLOW_TEST_DIR := $(TOP_DIR)/test/report-overflow
REPORT_OVERFLOW_TEST_OBJDIR := $(REPORT_OVERFLOW_TEST_DIR)/obj-asan
REPORT_OVERFLOW_TEST_BIN  := $(REPORT_OVERFLOW_TEST_DIR)/report-overflow-test
REPORT_OVERFLOW_TEST_SRCS := $(REPORT_OVERFLOW_TEST_DIR)/report_overflow_test.c
REPORT_OVERFLOW_TEST_OBJS := $(addprefix $(REPORT_OVERFLOW_TEST_OBJDIR)/, \
	$(addsuffix .o, $(basename $(notdir $(REPORT_OVERFLOW_TEST_SRCS)))))

# UBSan is not enabled here, as in test-snaplen-asan: it reports pre-existing
# misaligned loads in _get_packet_hash_number (pcap_capture.c).
$(REPORT_OVERFLOW_TEST_OBJS): $(REPORT_OVERFLOW_TEST_OBJDIR)/%.o: $(REPORT_OVERFLOW_TEST_DIR)/%.c
	@mkdir -p $(REPORT_OVERFLOW_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -fsanitize=address -c -o $@ $<

$(REPORT_OVERFLOW_TEST_BIN): $(REPORT_OVERFLOW_TEST_OBJS)
	$(QUIET) $(CC) $(CLDFLAGS) -fsanitize=address -o $@ $^ $(LIBS)

.PHONY: test-report-overflow
test-report-overflow: --check-dpi-folder $(REPORT_OVERFLOW_TEST_BIN)
	@echo "[TEST] report-overflow under ASan"
	$(QUIET) status=0; $(REPORT_OVERFLOW_TEST_BIN) || status=$$?; \
		$(RM) $(REPORT_OVERFLOW_TEST_OBJDIR) $(REPORT_OVERFLOW_TEST_BIN); exit $$status

# Dynamic-conf reply bounds: _reply() must truncate a reply longer than
# BUFFER_SIZE instead of sending stack bytes past the buffer to the client,
# the write loop must stop on error, command words must match whole
# commands, and an over-long dynamic-config.descriptor must be rejected at
# start-up. The driver is built with ASan and its objects live under
# test/dynconf-reply/ so a parallel `make -j test` does not race the normal
# build in src/.
DYNCONF_REPLY_TEST_DIR := $(TOP_DIR)/test/dynconf-reply
DYNCONF_REPLY_TEST_OBJDIR := $(DYNCONF_REPLY_TEST_DIR)/obj-asan
DYNCONF_REPLY_TEST_BIN  := $(DYNCONF_REPLY_TEST_DIR)/dynconf-reply-test
DYNCONF_REPLY_TEST_SRCS := $(DYNCONF_REPLY_TEST_DIR)/dynconf_reply_test.c
DYNCONF_REPLY_TEST_OBJS := $(addprefix $(DYNCONF_REPLY_TEST_OBJDIR)/, \
	$(addsuffix .o, $(basename $(notdir $(DYNCONF_REPLY_TEST_SRCS)))))

$(DYNCONF_REPLY_TEST_OBJS): $(DYNCONF_REPLY_TEST_OBJDIR)/%.o: $(DYNCONF_REPLY_TEST_DIR)/%.c
	@mkdir -p $(DYNCONF_REPLY_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -fsanitize=address -c -o $@ $<

$(DYNCONF_REPLY_TEST_BIN): $(DYNCONF_REPLY_TEST_OBJS)
	$(QUIET) $(CC) $(CLDFLAGS) -fsanitize=address -o $@ $^ $(LIBS)

.PHONY: test-dynconf-reply
test-dynconf-reply: --check-dpi-folder $(DYNCONF_REPLY_TEST_BIN)
	@echo "[TEST] dynconf-reply under ASan"
	$(QUIET) status=0; $(DYNCONF_REPLY_TEST_BIN) || status=$$?; \
		$(RM) $(DYNCONF_REPLY_TEST_OBJDIR) $(DYNCONF_REPLY_TEST_BIN); exit $$status

# Online-mode signal handling and exit statuses (issues #7 and #10): the
# supervisor forwards SIGTERM/SIGINT to the processing child and exits
# with its status; a start-up error reports the do-not-restart status and
# is not restarted; a SIGSEGV still restarts the child. The probe must be
# able to capture on the loopback interface (CAP_NET_RAW).
.PHONY: test-online-signals
test-online-signals: compile
	@echo "[TEST] online signal forwarding"
	$(QUIET) sh $(TOP_DIR)/test/online_signals.sh

# errno preservation across returning signal handlers (issues #7 and #10,
# review note N1): the SIGINT/SIGTERM/SIGRES arms of signal_handler()
# return to the interrupted code, so a libc call inside the handler - a
# failing best-effort write() - must not leave errno clobbered. The
# driver includes src/main.c for the real handler and is compiled with
# -ffunction-sections and linked with --gc-sections, so only the code the
# handler reaches is kept and the probe's own main() - renamed by the
# driver - is discarded; the single kept external, pcap_capture_stop, is
# stubbed there.
ERRNO_SIGNAL_TEST_DIR := $(TOP_DIR)/test/errno-signal
ERRNO_SIGNAL_TEST_OBJDIR := $(ERRNO_SIGNAL_TEST_DIR)/obj-asan
ERRNO_SIGNAL_TEST_BIN  := $(ERRNO_SIGNAL_TEST_DIR)/errno-signal-test
ERRNO_SIGNAL_TEST_SRCS := $(ERRNO_SIGNAL_TEST_DIR)/errno_signal_test.c
ERRNO_SIGNAL_TEST_OBJS := $(addprefix $(ERRNO_SIGNAL_TEST_OBJDIR)/, \
	$(addsuffix .o, $(basename $(notdir $(ERRNO_SIGNAL_TEST_SRCS)))))

$(ERRNO_SIGNAL_TEST_OBJS): $(ERRNO_SIGNAL_TEST_OBJDIR)/%.o: $(ERRNO_SIGNAL_TEST_DIR)/%.c $(SRC_DIR)/main.c
	@mkdir -p $(ERRNO_SIGNAL_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -ffunction-sections -fsanitize=address -c -o $@ $<

# $(CLDFLAGS) is not used here: its -rdynamic would export the renamed
# probe_main and root the whole discarded call graph under --gc-sections
$(ERRNO_SIGNAL_TEST_BIN): $(ERRNO_SIGNAL_TEST_OBJS)
	$(QUIET) $(CC) -fsanitize=address -Wl,--gc-sections -o $@ $^ $(LIBS)

.PHONY: test-errno-signal
test-errno-signal: --check-dpi-folder $(ERRNO_SIGNAL_TEST_BIN)
	@echo "[TEST] errno preserved across returning signal handlers"
	$(QUIET) status=0; $(ERRNO_SIGNAL_TEST_BIN) || status=$$?; \
		$(RM) $(ERRNO_SIGNAL_TEST_OBJDIR) $(ERRNO_SIGNAL_TEST_BIN); exit $$status

# Zero-length-key path of src/lib/hash.c (review #30/#31, note N3): an
# occupied slot can legitimately hold {key_len = 0, key = NULL} - an empty
# group-by makes mmt_memdup(msg, 0) return NULL - and hash_search must find
# it without reaching memcmp, whose pointer arguments are declared nonnull.
# Unlike the other drivers this one is built with UBSan as well as ASan: the
# removed memcmp(key, NULL, 0) call was UB, so the test is red on the
# unfixed hash.c and green on the fixed one. Its objects live under
# test/hash/ so a parallel `make -j test` does not race the build in src/.
HASH_TEST_DIR := $(TOP_DIR)/test/hash
HASH_TEST_OBJDIR := $(HASH_TEST_DIR)/obj-asan-ubsan
HASH_TEST_BIN  := $(HASH_TEST_DIR)/hash-test
HASH_TEST_SRCS := $(HASH_TEST_DIR)/hash_test.c
HASH_TEST_OBJS := $(addprefix $(HASH_TEST_OBJDIR)/, \
	$(addsuffix .o, $(basename $(notdir $(HASH_TEST_SRCS)))))

# -fno-sanitize-recover makes a UBSan report fatal, so the leg fails rather
# than passing with a printed report on the unfixed code
$(HASH_TEST_OBJS): $(HASH_TEST_OBJDIR)/%.o: $(HASH_TEST_DIR)/%.c $(SRC_DIR)/lib/hash.c
	@mkdir -p $(HASH_TEST_OBJDIR)
	$(QUIET) $(CC) $(CFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=undefined -c -o $@ $<

$(HASH_TEST_BIN): $(HASH_TEST_OBJS)
	$(QUIET) $(CC) $(CLDFLAGS) -fsanitize=address,undefined -o $@ $^

.PHONY: test-hash
test-hash: $(HASH_TEST_BIN)
	@echo "[TEST] hash zero-length key under ASan+UBSan"
	$(QUIET) status=0; $(HASH_TEST_BIN) || status=$$?; \
		$(RM) $(HASH_TEST_OBJDIR) $(HASH_TEST_BIN); exit $$status

# Required file/dir/descriptor options (review #35, note N3): an enabled
# file output without output-file made file_output_alloc_init() pass NULL
# to strlen() and die by SIGSEGV before any packet was read. Every missing
# path - file-output/behaviour output-file and output-dir, and the
# dump-pcap, socket-output, reconstruct-data and dynamic-config path
# options on the builds that have those modules - must be rejected by
# conf_validate() with an error naming the 'section.key' option, a
# non-zero exit and no crash. The compile prerequisite keeps a parallel
# `make -j test` on a clean tree from racing the build.
.PHONY: test-file-output-unset
test-file-output-unset: compile
	@echo "[TEST] file output without output-file"
	$(QUIET) sh $(TOP_DIR)/test/file-output-unset/check_file_output_unset.sh $(TOP_DIR)/$(APP)

# Enum-like option values (issue #39): output.format takes CSV or JSON,
# case-insensitive, in the configuration file and through -X alike, and
# every spelling writes the same report; a refused value - a number or an
# unknown name - must be reported with the accepted names and a non-zero
# exit, and -x must list those names instead of the storage type. The
# other enum-like -X options of the build are checked the same way. The
# compile prerequisite keeps a parallel `make -j test` on a clean tree
# from racing the build.
.PHONY: test-output-format
test-output-format: compile
	@echo "[TEST] output.format and enum-like -X values"
	$(QUIET) sh $(TOP_DIR)/test/output-format/check_output_format.sh $(TOP_DIR)/$(APP)

# MQTT counted in conf_update_output_enable() (issue #40): an MQTT-only
# enabled output was dropped from the "any output enabled" flag, leaving
# context->output NULL. The check runs a conf whose only enabled channel is
# an MQTT broker that refuses the connection: the output must exist
# (reports reach stdout; on an MQTT_MODULE build the failed connect is
# logged, not fatal), and disabling it in the file stays clean. The
# compile prerequisite keeps a parallel `make -j test` on a clean tree
# from racing the build.
.PHONY: test-mqtt-output
test-mqtt-output: compile
	@echo "[TEST] mqtt-only output enable"
	$(QUIET) sh $(TOP_DIR)/test/mqtt-output/check_mqtt_output.sh $(TOP_DIR)/$(APP)

# MQTT on a dead channel (issue #53, review F2): once the init connect
# failed, mqtt_output_send() dropped every report silently and never
# retried. The check feeds the pcap through a FIFO held open while
# system-report ticks one report every 5 seconds onto the mqtt+stdout
# channels: with no broker at all the drops must be counted, warned about
# once per interval and retried; with a broker container coming up after
# the probe, the periodic retry must connect and deliver. Both legs need
# an MQTT_MODULE build (they skip otherwise), the second one needs docker.
.PHONY: test-mqtt-dead-channel
test-mqtt-dead-channel: compile
	@echo "[TEST] mqtt dead channel"
	$(QUIET) sh $(TOP_DIR)/test/mqtt-output/check_mqtt_dead_channel.sh $(TOP_DIR)/$(APP)

# system-report.output-channel (issue #43): declared CHAR_STAR over an
# output_channel_conf_t field, so a -X override freed and cloned a string
# into the enum and died by SIGSEGV. Declared LIST like the other
# *.output-channel keys, it must accept the channel spellings the
# configuration file accepts - a name, a list - and write the system
# report to the file output; a malformed list in the file is refused. The
# system-stats routine writes one report every 5 seconds, so the legs feed
# the pcap through a FIFO held open for a report to fire. The compile
# prerequisite keeps a parallel `make -j test` on a clean tree from racing
# the build.
.PHONY: test-sysreport-channel
test-sysreport-channel: compile
	@echo "[TEST] system-report.output-channel -X values"
	$(QUIET) sh $(TOP_DIR)/test/sysreport-channel/check_sysreport_channel.sh $(TOP_DIR)/$(APP)

# End-of-capture alert delivery (issue #38): every alert MMT-Security raises
# during an offline capture must be written before the probe exits, on every
# run. Runs ./probe RUNS times (default 3) per leg on a generated capture
# whose last packets each raise one alert of rule 13 - thread-nb 0, 1 and 3,
# the engine in the worker thread or in 1 or 2 threads of its own, CSV and
# JSON, plain and sampled files - and on test/UA-Exp01.pcap with 3 workers,
# checking that the reports written equal the alerts raised. Skipped on a
# build without SECURITY_MODULE or without the installed rules. The compile
# prerequisite keeps a parallel `make -j test` on a clean tree from racing
# the build.
.PHONY: test-alert-delivery
test-alert-delivery: compile
	@echo "[TEST] end-of-capture alert delivery"
	$(QUIET) sh $(TOP_DIR)/test/alert-delivery/check_alert_delivery.sh $(TOP_DIR)/$(APP)

# Uninitialised `now` on the offline timer path (issue #46): the empty-ring
# branch of _worker_thread fed an uninitialised struct timeval to
# worker_update_timer until a first packet set it. Runs the probe under
# valgrind memcheck on a single-flow capture with thread-nb = 3 - the
# workers the flow never reaches spin on their empty rings and would feed
# the uninitialised timestamp on every iteration - and on
# test/UA-Exp01.pcap, asserting no uninitialised-value report. Skipped when
# valgrind is not installed. The compile prerequisite keeps a parallel
# `make -j test` on a clean tree from racing the build.
.PHONY: test-uninit-timer
test-uninit-timer: compile
	@echo "[TEST] uninitialised offline timer (valgrind)"
	$(QUIET) sh $(TOP_DIR)/test/uninit-timer/check_uninit_timer.sh $(TOP_DIR)/$(APP)

.PHONY: test
test: test-stix test-report-overflow-stix test-snaplen test-crash test-report-overflow test-dynconf-reply test-online-signals test-errno-signal test-hash test-file-output-unset test-output-format test-sysreport-channel test-alert-delivery test-mqtt-output test-mqtt-dead-channel test-uninit-timer
	@:
