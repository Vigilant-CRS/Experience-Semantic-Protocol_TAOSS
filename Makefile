# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Standard commands (master plan section 52). `make verify` is the local
# gate before every pull request.

UV ?= uv
RUN := $(UV) run --frozen

.PHONY: setup lint format typecheck unit property integration security fuzz-smoke \
        conformance milestone benchmark-smoke verify-plan reuse coverage verify clean

setup:
	$(UV) sync --frozen

lint:
	$(RUN) ruff check src tests scripts
	$(RUN) ruff format --check src tests scripts

format:
	$(RUN) ruff format src tests scripts
	$(RUN) ruff check --fix src tests scripts

typecheck:
	$(RUN) mypy

unit:
	$(RUN) pytest tests/unit -q

property:
	$(RUN) pytest tests/property -q

integration:
	$(RUN) pytest tests/integration -q

security:
	$(RUN) pytest tests/security -q

fuzz-smoke:
	$(RUN) pytest tests/fuzz -q

conformance:
	$(RUN) pytest tests/conformance -q

milestone:
	$(RUN) pytest tests/milestone -q

benchmark-smoke:
	@echo "benchmark-smoke: no benchmarks yet (WP-034)"

verify-plan:
	$(RUN) python scripts/verify_plan_sync.py

reuse:
	$(RUN) reuse lint

coverage:
	$(RUN) pytest --cov --cov-report=term-missing -q

verify: lint typecheck reuse verify-plan
	$(RUN) pytest -q

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build
