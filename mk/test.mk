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

# Exit-status regression (issue #2): an offline crash must die by the
# signal (a shell reports 128+signum), clean shutdowns (end of pcap,
# SIGINT, SIGTERM) must exit 0. Needs the compiled probe binary — run
# `make ... compile` first.
.PHONY: test-crash
test-crash:
	@echo "[TEST] crash exit status"
	$(QUIET) sh $(TOP_DIR)/test/crash_exit_status.sh

# Aggregate: `make test` runs every suite. PR #3's test-snaplen joins the
# prerequisites when the two branches are merged.
.PHONY: test
test: test-stix test-crash
	@:
