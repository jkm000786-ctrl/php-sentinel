# PHP Sentinel

Evidence-driven PHP exposure and vulnerability assessment tooling.

## Current intelligence baseline

Initial policy covers the PHP security release of 2026-10-21:

- CVE-2026-109618
- CVE-2026-109619
- Upstream fixed releases: PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35

PHP Sentinel does not treat a version banner as proof of vulnerability.


## Security architecture

PHP Sentinel uses an evidence-driven, fail-closed intelligence trust model.
Remote intelligence workflows authenticate the signed source registry, enforce
HTTPS/public-destination transport policy, refuse redirects, verify the actual
connected peer against the prevalidated DNS set, and still require independent
manifest signature and lifecycle verification.

See
[`docs/02-threat-model.md`](docs/02-threat-model.md)
for the v1 threat model and
[`docs/48-v1-security-review-threat-model-closure.md`](docs/48-v1-security-review-threat-model-closure.md)
for the Phase 44 security review and residual-risk closure.

## WSL setup

```bash
cd /mnt/c/Users/hp/projects
unzip php-sentinel-starter.zip
cd php-sentinel

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

php-sentinel --help
pytest -q
```

## Docker

```bash
docker compose build scanner
docker compose --profile lab up -d patched-php
docker compose run --rm scanner analyze http://host.docker.internal:8080
```

Only assess systems you own or are explicitly authorized to test.
