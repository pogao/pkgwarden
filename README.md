# pkgwarden

pkgwarden is a package proxy for npm, PyPI, RubyGems, Go modules, and Cargo. You point your package managers at it instead of the public registries. It fetches metadata and files from those registries and refuses releases that are too new, known to be malicious or vulnerable, or that look suspicious.

Many supply-chain attacks arrive as a new release. A hijacked maintainer account publishes a poisoned version, or a look-alike name appears next to a popular package. pkgwarden holds new releases back long enough for registries and advisory databases to catch them, and it checks every release against those databases before a client can download it.

Package managers keep working normally through it. pkgwarden removes blocked versions from the metadata it serves, so a resolver picks the newest allowed version on its own. A direct download of a blocked version gets HTTP 403, and the client prints the reason. This npm output is trimmed after the second line:

	npm error code E403
	npm error 403 403 Forbidden - GET http://127.0.0.1:18181/npm/lodash/-/lodash-4.17.20.tgz - pkgwarden blocked npm/lodash@4.17.20: advisory/vulnerability: GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm; advisory/vulnerability: GHSA-r5fr-rjxr-66jc (high vulnerability, via osv): lodash vulnerable to Code Injection via `_.template` imports key names https://osv... (request 0d43614cae40e59f3c498ff91116a7be)
	...

## Features

- **Cooldown.** pkgwarden hides and refuses releases younger than 7 days. `-cooldown` sets the wait. See [Cooldown](docs/cooldown.md).
- **Malicious package blocking.** pkgwarden always blocks releases that OSV, the GitHub Advisory Database, or the OpenSSF malicious-packages dataset lists as malicious. See [Advisories](docs/advisories.md).
- **Vulnerability blocking.** pkgwarden blocks releases with a high or critical vulnerability and serves lower-rated ones with a warning. `-block-severity` sets the threshold. See [Advisories](docs/advisories.md#the-severity-threshold).
- **Suspicious-package heuristics.** Typosquat names, brand-new packages, low download counts, new publishers, and new npm install scripts add up to a score that warns or blocks. See [Heuristics](docs/heuristics.md).
- **Filtered metadata and refused downloads.** Resolvers never see blocked versions, and lockfiles or direct URLs that name one get a 403 with the reason. See [How pkgwarden works](docs/how-it-works.md).
- **Allowlist.** Packages you trust skip every check. See [`-allow`](docs/configuration.md#-allow).
- **Check API.** `GET /api/v1/check` tells you why a release is blocked without downloading it. See [HTTP API reference](docs/api.md).
- **Prometheus metrics.** `/metrics` counts requests, served and blocked downloads, upstream errors, and cache hits, and shows how fresh the OpenSSF index is. Blocks are counted per rule, so malicious, vulnerable, cooldown, and typosquat blocks show up separately. See [Metrics and request tracing](docs/observability.md).
- **Request tracing.** Every log line about a request carries one request ID, from the inbound request through each registry and advisory call. The ID is in the `X-Request-Id` header and at the end of every 403 message. See [Follow one request through the logs](docs/observability.md#follow-one-request-through-the-logs).
- **Five ecosystems.** One proxy serves npm, pnpm, Yarn, pip, uv, Poetry, Bundler, gem, Go, and Cargo. See [Point your package managers at pkgwarden](docs/package-managers.md).

## Quick start

Build and run the image:

	docker build -t pkgwarden .
	docker run -p 8080:8080 pkgwarden

Point npm at it, and install as usual:

	npm config set registry http://localhost:8080/npm/
	npm install express

To ask why a release is blocked, run this:

	curl 'http://localhost:8080/api/v1/check?ecosystem=npm&name=lodash&version=4.17.20'

To set up pip, uv, Poetry, Bundler, gem, Go, Cargo, pnpm, or Yarn, see [Point your package managers at pkgwarden](docs/package-managers.md). To run pkgwarden behind TLS or from source, see [Deploy pkgwarden](docs/deployment.md).

## Documentation

- [How pkgwarden works](docs/how-it-works.md) explains the request flow, the two layers of blocking, and what pkgwarden does not do.
- [Cooldown](docs/cooldown.md) covers the minimum release age and how each ecosystem measures it.
- [Advisories](docs/advisories.md) covers the advisory sources, severity ratings, merging, caching, and failure behavior.
- [Heuristics](docs/heuristics.md) lists every signal and weight, the scoring rules, and typosquat detection.
- [Point your package managers at pkgwarden](docs/package-managers.md) sets up each client and shows what it prints for a blocked release.
- [Configuration reference](docs/configuration.md) lists every flag and environment variable, with example configurations.
- [HTTP API reference](docs/api.md) documents `/api/v1/check`, `/healthz`, `/metrics`, the response headers, the 403 body, and every route.
- [Deploy pkgwarden](docs/deployment.md) covers the image, TLS, egress, logs, Prometheus scraping, shutdown, and security.
- [Metrics and request tracing](docs/observability.md) lists every metric with example queries and shows how to follow one request through the logs.
- [Develop pkgwarden](docs/development.md) covers the code layout, the tests, and adding an ecosystem.

## Development

Run `go test -race ./...` for the unit tests and `scripts/e2e.sh` for the end-to-end check with real clients. See [Develop pkgwarden](docs/development.md).
