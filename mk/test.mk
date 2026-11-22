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

#####################################################
# INTEGRATION CHECKS                                #
#####################################################

# Integration check of the PCAP snap-len/worker-ring sizing (issue #1).
# Runs ./probe over two generated captures (1500-B and 64-B frames) for each
# snap-len in {0, 64, 65535} and each thread-nb in {1, 2}, asserting every
# packet is processed and no run crashes. Needs a built probe and python3;
# the captures are written under a temporary directory.
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

.PHONY: test
test: test-stix test-snaplen
	@:
