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

.PHONY: test
test: test-snaplen test-crash test-report-overflow
	@:
