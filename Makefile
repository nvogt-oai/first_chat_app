.PHONY: help setup run
.PHONY: test

PY ?= python
ifeq ($(wildcard .venv/bin/python),.venv/bin/python)
PY := .venv/bin/python
endif

help:
	@echo "make setup  - create venv + install deps"
	@echo "make run    - run locally (loads local.env; starts ngrok automatically if NGROK_AUTHTOKEN is set)"
	@echo "make test   - run tests"

setup:
	./scripts/setup.sh

run:
	./scripts/run.sh

test:
	$(PY) -m pytest -q


