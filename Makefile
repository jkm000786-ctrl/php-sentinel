.PHONY: install test lint release-check release-check-dev python-matrix reproducible-wheel sdist-check docker-build docker-lab-up docker-down

install:
	python3 -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

release-check:
	python3 scripts/release_check.py

release-check-dev:
	python3 scripts/release_check.py --allow-dirty

python-matrix:
	python3 scripts/python_matrix_check.py

reproducible-wheel:
	python3 scripts/reproducible_wheel_check.py

sdist-check:
	python3 scripts/sdist_check.py

docker-build:
	docker compose build scanner

docker-lab-up:
	docker compose --profile lab up -d patched-php

docker-down:
	docker compose --profile lab down
