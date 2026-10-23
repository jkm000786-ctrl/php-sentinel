.PHONY: install test lint docker-build docker-lab-up docker-down

install:
	python3 -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

docker-build:
	docker compose build scanner

docker-lab-up:
	docker compose --profile lab up -d patched-php

docker-down:
	docker compose --profile lab down
