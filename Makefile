# Runs the standalone rego policy test suites. Each control keeps its own
# tests/ dir (shunit2 helpers, fixtures, runner) so it can be exercised in
# isolation. CI gates the build on both in a single call:
#
#   make test-provenance test-sbom

.PHONY: test-provenance test-sbom

test-provenance:
	./SDLC-CTRL-0002/tests/run_tests.sh

test-sbom:
	./SDLC-CTRL-0004/tests/run_tests.sh
