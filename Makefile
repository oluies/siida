# Siida — top-level developer entry point.
#
# Thin wrapper over the project-pinned Mill build (see .mill-version,
# build.mill, and specs/001-project-bootstrap/quickstart.md). Mill
# manages its own up-to-date checks; every target is .PHONY.

MILL ?= ./mill

.PHONY: help all check build compile test headers ci-parity resolve clean

help:
	@echo "Siida — developer commands"
	@echo ""
	@echo "  make build       compile every module"
	@echo "  make test        run every module's smoke test"
	@echo "  make check       headers + compile + test + ci-parity (CI-equivalent)"
	@echo "  make headers     run the licence-header check"
	@echo "  make ci-parity   verify GitHub and Forgejo workflows match"
	@echo "  make resolve     sanity-check that Mill parses build.mill"
	@echo "  make clean       remove Mill output (out/)"
	@echo ""
	@echo "  MILL=<path>      override the Mill launcher (default: ./mill)"

all: check

build: compile

compile:
	$(MILL) __.compile

test:
	$(MILL) __.test

headers:
	$(MILL) SiidaBuild.millSiidaHeaderCheck

ci-parity:
	bash scripts/check-ci-parity.sh

resolve:
	$(MILL) resolve _

check: headers compile test ci-parity

clean:
	rm -rf out
