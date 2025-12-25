.PHONY: help setup run

help:
	@echo "make setup  - create venv + install deps"
	@echo "make run    - run locally (loads local.env; starts ngrok automatically if NGROK_AUTHTOKEN is set)"

setup:
	./scripts/setup.sh

run:
	./scripts/run.sh


