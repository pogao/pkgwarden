# Develop pkgwarden

This guide covers the code layout, the tests, adding an ecosystem, and refreshing the popular-package lists. You need Go 1.27.3 or later. The end-to-end script also needs Docker and network access.

## Find your way around the code

	cmd/pkgwarden/          flags, startup, and shutdown
	internal/ecosystem/     ecosystem names, advisory database names, and name normalization
	internal/policy/        the engine: allowlist, cooldown, advisories, heuristics, typosquats
	internal/policy/popular/  one popular-package list per ecosystem, embedded at build time
	internal/advisory/      the OSV, GHSA, and OpenSSF sources, merging, caching, and CVSS scoring
	internal/version/       version ordering for SemVer, PEP 440, and Gem::Version
	internal/cache/         the in-memory TTL cache
	internal/proxy/         the server, upstream access, and 403 responses shared by every adapter
	internal/telemetry/     Prometheus metrics, request IDs, and the request and upstream log lines
	internal/telemetry/telemetrytest/  reads /metrics and captures logs for tests
	internal/proxy/npm/     the npm adapter
	internal/proxy/pypi/    the PyPI adapter
	internal/proxy/rubygems/  the RubyGems adapter
	internal/proxy/goproxy/   the Go module proxy adapter
	internal/proxy/cargo/   the Cargo adapter
	scripts/e2e.sh          the end-to-end check with real clients
	Dockerfile              the container image

Each adapter translates one registry protocol to and from `policy.Package`. The engine never sees a protocol. [How pkgwarden works](how-it-works.md) explains the flow between them.

## Run the tests

To run every unit test with the race detector, run this from the repository root:

	go test -race ./...

The unit tests run against local test servers and recorded upstream responses in the `testdata/` directories.

To run one package's tests, name the package:

	go test ./internal/policy/

## Run the end-to-end check

To check pkgwarden against the real registries and clients, run this:

	./scripts/e2e.sh

The script builds the image as `pkgwarden:e2e`, starts it with `-log-level debug` in a container and on a Docker network both named `pkgwarden-e2e-<pid>`, and publishes it on `127.0.0.1:18080`. Clients reach it as `pkgwarden`, its alias on that network. It then runs each client in its own container, from the images `node:22-alpine`, `python:3.13-slim`, `golang:1.27-alpine`, `rust:1-slim`, and `ruby:3.3-slim`. When it finishes, it saves the proxy's log to `e2e-pkgwarden.log` and removes the container and the network.

The script checks these behaviors:

| Ecosystem | Check |
| --- | --- |
| npm | `npm install express` succeeds. |
| npm | `npm install lodash@4.17.20` fails, because the release has a high vulnerability. |
| npm | The tarball of `lodash@4.17.20` gets a 403 that names the advisory. |
| npm | The tarball of `event-stream@3.3.6`, a malicious release npm unpublished, gets a 403. |
| npm | `/npm/lodash/`, with a trailing slash, does not list `lodash@4.17.20`. |
| npm | The tarball `express-3.0.0rc3.tgz` of `express@3.0.0-rc3` downloads. |
| npm | No `@types/node` release younger than 7 days appears in the packument, `latest` is not one of them, and tarball links point at pkgwarden. |
| PyPI | `pip download requests` succeeds. |
| PyPI | The PEP 691 JSON page for `requests` lists files whose URLs point at pkgwarden. |
| PyPI | `pip download requests==2.31.0` succeeds, because the release has only medium vulnerabilities. |
| PyPI | `/api/v1/check` rates `requests` 2.31.0 as `warn`. |
| PyPI | `pip download urllib3==1.24.1` fails. |
| PyPI | The wheel of `urllib3` 1.24.1 gets a 403 that names the advisory. |
| Go | `go get golang.org/x/text@latest` succeeds. |
| Go | `go get golang.org/x/text@v0.3.6` fails with pkgwarden's 403. |
| Cargo | `cargo fetch` of `itoa = "1"` downloads the crate through the `pkgwarden` source. |
| Cargo | `cargo fetch` of `smallvec = "=1.6.0"` fails to select a version. |
| Cargo | The download of `smallvec` 1.6.0 gets a 403 that names the advisory. |
| RubyGems | `bundle install` of `rack ~> 3.0` succeeds through the mirror. |
| RubyGems | `bundle install` of `rack = 2.2.3` fails. |
| RubyGems | The download of `rack-2.2.3.gem` gets a 403 that names the advisory. |
| All | `/metrics` counts at least one served artifact and one block for every ecosystem. |
| npm | An allowed download sent with its own `X-Request-Id` has a `request` line and an `upstream` line with that ID in the log. |
| npm | A blocked download's 403 body ends with its request ID, and that ID has a `request` line and a `blocked` line. |

It prints `PASS` or `FAIL` for each check, and exits with status 1 if any check failed. The checks depend on live registry and advisory data. A new advisory for `requests` 2.31.0, for example, would fail a check without any code change.

The script needs port 18080 free. It exits with status 1 before any check if it cannot create the network, start the container, or get an answer from `/healthz` within 30 seconds.

## Add an ecosystem adapter

An adapter serves one registry protocol under `/<ecosystem>/` and describes packages to the engine. To add one, follow these steps:

1. In `internal/ecosystem/ecosystem.go`, add an `Ecosystem` constant, its row in `table` with the OSV name, the GitHub name, and the registry's name normalization, and the constant in `All`.
2. In `internal/version/version.go`, make `Compare` order the ecosystem's versions. Advisory ranges depend on it.
3. Add `internal/policy/popular/<ecosystem>.txt` with at least 250 names. `TestPopularNamesAreNotTyposquats` reads a list for every ecosystem in `All` and fails below that count.
4. Create `internal/proxy/<ecosystem>/` with a type that implements `proxy.Registry`. That means `ServeHTTP` for requests relative to the mount point, `Ecosystem`, and `Package`, which returns a `policy.Package`.
5. Mount the adapter in `cmd/pkgwarden/main.go` by adding it to the `proxy.NewServer` call.
6. Add unit tests with recorded responses under `testdata/`, and add checks for a working install, a refused install, and a 403 body to `scripts/e2e.sh`.
7. Document the client setup in `docs/package-managers.md` and the routes in `docs/api.md`.

Inside the adapter, reuse the shared pieces in `internal/proxy`:

- Fetch metadata with `Upstream.Fetch` or `Upstream.FetchJSON`, which cache it. Open artifacts with `Upstream.Open`, which does not. Copy a release's file to the client with `ServeArtifact`, which counts it in the artifact metrics, and anything else with `Relay`.
- Call `Engine.Assess` once per request. Pass the package verdict to `Enforce` with `StageMetadata` before you serve metadata, and drop each version for which `Assessment.Allowed` is false.
- Pass `Assessment.Release(version)` to `Enforce` with `StageArtifact` before you serve a file. `Enforce` counts the decision, writes the 403, and returns false when the verdict blocks.
- Pass the request's context to `Enforce`, `ServeArtifact`, and every `Upstream` call, and log with the `slog` `Context` functions, so that every line carries the request ID.
- Build absolute links with `BaseURL(req, publicURL)`.
- Map upstream failures with `WriteError`, which answers 404 for a missing resource and 502 otherwise.
- Copy only named request headers upstream, never the whole header set, so client credentials stay with pkgwarden.

Answer every block with `Enforce`, never with a 404 or 410. [How pkgwarden works](how-it-works.md#a-block-is-always-a-403) explains why.

## Refresh the popular-package lists

The lists in `internal/policy/popular/` are embedded in the binary. A change reaches users only with a new build. To refresh one, follow these steps:

1. Rank candidate packages by downloads. The registries pkgwarden already reads publish the counts. npm has `https://api.npmjs.org/downloads/point/last-week/<name>`, PyPI has `https://pypistats.org/api/packages/<name>/recent`, crates.io has `recent_downloads` in `https://crates.io/api/v1/crates/<name>`, and RubyGems has `downloads` in `https://rubygems.org/api/v1/gems/<name>.json`.
2. Keep packages that people name in an install command or a manifest. Leave out deep transitive dependencies. Lockfiles name those exactly, and their generic names would only add false positives.
3. Edit the file. Write one name per line, spelled as the registry spells it. Keep the comment lines at the top. A `#` starts a comment. For Go, write full module paths.
4. Check each new name that is short or generic. Every listed name widens what counts as a typosquat. For example, `sidekiq-cron` on the RubyGems list makes `sidekiq-pro` warn.
5. Run the policy tests:

		go test ./internal/policy/

6. Count the names, and update the table in `docs/heuristics.md`:

		grep -vc '^#' internal/policy/popular/*.txt

7. Build and deploy a new binary or image.
