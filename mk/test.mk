#####################################################
# INTEGRATION CHECKS                                #
#####################################################

# Integration check of the PCAP snap-len/worker-ring sizing (issue #1).
# Runs ./probe over generated captures (1500-B and 64-B frames, plus one
# declaring a snap length of 0x7FFFFFFF) for each snap-len in {0, 64, 65535}
# and each thread-nb in {1, 2}, asserting every packet is processed, no run
# crashes, and the file-declared snap length cannot grow the rings past
# 262144. Needs a built probe and python3; the captures are written under
# a temporary directory.
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
test: test-snaplen
	@:
