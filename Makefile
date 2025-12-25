.PHONY: help setup run
.PHONY: reset-data
.PHONY: test

PY ?= python
ifeq ($(wildcard .venv/bin/python),.venv/bin/python)
PY := .venv/bin/python
endif

help:
	@echo "make setup  - create venv + install deps"
	@echo "make run    - run locally (loads local.env; starts ngrok automatically if NGROK_AUTHTOKEN is set)"
	@echo "make reset-data - delete local persisted JSON state under ./data"
	@echo "make test   - run tests"

setup:
	./scripts/setup.sh

run:
	./scripts/run.sh

clear:
	@echo "Clearing persisted state under ./data ..."
	@rm -f ./data/auth/*.json
	@rm -f ./data/calories/users/*.json
	@mkdir -p ./data/auth ./data/calories/users
	@echo "Done."

test:
	$(PY) -m pytest -q


