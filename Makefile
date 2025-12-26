.PHONY: help setup run run-local
.PHONY: inspector
.PHONY: inspector-local
.PHONY: reset-data
.PHONY: test

PY ?= python
ifeq ($(wildcard .venv/bin/python),.venv/bin/python)
PY := .venv/bin/python
endif

help:
	@echo "make setup  - create venv + install deps"
	@echo "make run    - run locally (loads local.env; starts ngrok automatically if NGROK_AUTHTOKEN is set)"
	@echo "make run-local - run locally without loading local.env (forces localhost issuer/metadata; disables ngrok)"
	@echo "make inspector - run MCP Inspector UI (requires Node.js / npx)"
	@echo "make inspector-local - alias of inspector (intended for use with make run-local)"
	@echo "make reset-data - delete local persisted JSON state under ./data"
	@echo "make test   - run tests"

setup:
	./scripts/setup.sh

run:
	./scripts/run.sh

run-local:
	@SKIP_LOCAL_ENV=1 \
	NGROK_AUTHTOKEN= \
	PUBLIC_BASE_URL= \
	LOCAL_BASE_URL=http://127.0.0.1:8000 \
	RESOURCE_SERVER_URL=http://127.0.0.1:8000/mcp \
	./scripts/run.sh

inspector:
	@npx --yes @modelcontextprotocol/inspector

inspector-local: inspector

clear:
	@echo "Clearing persisted state under ./data ..."
	@rm -f ./data/auth/*.json
	@rm -f ./data/calories/users/*.json
	@mkdir -p ./data/auth ./data/calories/users
	@echo "Done."

test:
	$(PY) -m pytest -q


