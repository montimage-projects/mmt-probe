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

$(ERRNO_SIGNAL_TEST_OBJS): $(ERRNO_SIGNAL_TEST_OBJDIR)/%.o: $(ERRNO_SIGNAL_TEST_DIR)/%.c
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

.PHONY: test
test: test-snaplen test-crash test-report-overflow test-dynconf-reply test-online-signals test-errno-signal
	@:
