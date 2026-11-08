# Configuration reference

pkgwarden reads its configuration from command-line flags and environment variables. It has no configuration file. The flags are defined in `cmd/pkgwarden/config.go`.

## Help output

This is the output of `env -u GITHUB_TOKEN go run ./cmd/pkgwarden -h 2>&1` at the current commit. The help goes to stderr, and the command exits with status 0. Rerun it to check this page.

	Usage of pkgwarden:
	  -advisory-ttl duration
	    	how long advisory lookups are cached (default 1h0m0s)
	  -allow string
	    	comma-separated ecosystem:name packages exempt from every check, e.g. npm:my-internal-lib
	  -block-severity string
	    	lowest vulnerability rating that blocks a release: low, medium, high, critical or none (lower and unrated ones warn; malicious releases always block) (default "high")
	  -cooldown duration
	    	minimum age of a release before it is served (0 disables) (default 168h0m0s)
	  -fail-open
	    	serve packages when advisory sources are unreachable
	  -ghsa-token string
	    	GitHub token; enables direct GitHub Advisory Database lookups (default $GITHUB_TOKEN)
	  -heuristics
	    	score suspicious-package signals (default true)
	  -heuristics-block int
	    	heuristic score at which a release is blocked (default 70)
	  -heuristics-warn int
	    	heuristic score at which a release is served with a warning (default 30)
	  -listen string
	    	address to listen on (default ":8080")
	  -log-level value
	    	debug, info, warn or error (default INFO)
	  -low-downloads int
	    	weekly downloads below this count as unpopular (default 100)
	  -metadata-ttl duration
	    	how long upstream metadata is cached (default 5m0s)
	  -metrics-listen string
	    	address of a separate listener that alone serves /metrics (default: /metrics is served on -listen)
	  -new-package-age duration
	    	packages younger than this count as new (default 720h0m0s)
	  -openssf
	    	sync the OpenSSF malicious-packages dataset locally (about 300 MB download per refresh)
	  -openssf-refresh duration
	    	how often the OpenSSF dataset is refreshed (default 6h0m0s)
	  -osv-url string
	    	OSV API base URL (default "https://api.osv.dev")
	  -public-url string
	    	externally visible base URL, used in rewritten download links (default: derived from each request)

There are 19 flags. To count them, run this:

	go run ./cmd/pkgwarden -h 2>&1 | grep -c '^  -'

## Environment variables and precedence

Every flag has an environment variable named `PKGWARDEN_` followed by the flag name in upper case, with each `-` changed to `_`. `-cooldown` becomes `PKGWARDEN_COOLDOWN`, and `-block-severity` becomes `PKGWARDEN_BLOCK_SEVERITY`.

pkgwarden resolves each flag in this order, and the first source that is set wins:

1. The command-line flag.
2. The `PKGWARDEN_` environment variable.
3. For `-ghsa-token` only, the `GITHUB_TOKEN` environment variable.
4. The built-in default.

A command-line flag replaces the environment value. It does not add to it. `-allow npm:a` with `PKGWARDEN_ALLOW=npm:b` allowlists only `npm:a`.

## Value types

| Type | Accepted values |
| --- | --- |
| duration | A Go duration, such as `300ms`, `90s`, `5m`, `1h30m`, or `168h`. The units are `ns`, `us`, `ms`, `s`, `m`, and `h`. There is no unit for days. |
| int | A decimal integer. |
| bool | `1`, `t`, `T`, `TRUE`, `true`, `True`, `0`, `f`, `F`, `FALSE`, `false`, or `False`. On the command line, write a false value with `=`, such as `-heuristics=false`. A bare `-heuristics` means true. |
| string | Any text. |
| level | `debug`, `info`, `warn`, or `error`, in any case. |

## All flags

| Flag | Type | Default | Environment variable |
| --- | --- | --- | --- |
| `-advisory-ttl` | duration | `1h0m0s` | `PKGWARDEN_ADVISORY_TTL` |
| `-allow` | string | empty | `PKGWARDEN_ALLOW` |
| `-block-severity` | string | `high` | `PKGWARDEN_BLOCK_SEVERITY` |
| `-cooldown` | duration | `168h0m0s` | `PKGWARDEN_COOLDOWN` |
| `-fail-open` | bool | `false` | `PKGWARDEN_FAIL_OPEN` |
| `-ghsa-token` | string | value of `GITHUB_TOKEN` | `PKGWARDEN_GHSA_TOKEN` |
| `-heuristics` | bool | `true` | `PKGWARDEN_HEURISTICS` |
| `-heuristics-block` | int | `70` | `PKGWARDEN_HEURISTICS_BLOCK` |
| `-heuristics-warn` | int | `30` | `PKGWARDEN_HEURISTICS_WARN` |
| `-listen` | string | `:8080` | `PKGWARDEN_LISTEN` |
| `-log-level` | level | `info` | `PKGWARDEN_LOG_LEVEL` |
| `-low-downloads` | int | `100` | `PKGWARDEN_LOW_DOWNLOADS` |
| `-metadata-ttl` | duration | `5m0s` | `PKGWARDEN_METADATA_TTL` |
| `-metrics-listen` | string | empty, `/metrics` is served on `-listen` | `PKGWARDEN_METRICS_LISTEN` |
| `-new-package-age` | duration | `720h0m0s` | `PKGWARDEN_NEW_PACKAGE_AGE` |
| `-openssf` | bool | `false` | `PKGWARDEN_OPENSSF` |
| `-openssf-refresh` | duration | `6h0m0s` | `PKGWARDEN_OPENSSF_REFRESH` |
| `-osv-url` | string | `https://api.osv.dev` | `PKGWARDEN_OSV_URL` |
| `-public-url` | string | empty, derived from each request | `PKGWARDEN_PUBLIC_URL` |

## Server flags

### `-listen`

The TCP address the HTTP server listens on, in Go's `host:port` form. `:8080` listens on every interface. `127.0.0.1:8080` listens on loopback only. pkgwarden serves plain HTTP and has no TLS settings.

### `-metrics-listen`

The TCP address of a second HTTP listener that serves only `GET /metrics`, in the same form as `-listen`. When it is set, the main listener answers 404 for `/metrics`. When it is empty, the main listener serves `/metrics` next to `/healthz`. Both listeners shut down together. See [Metrics and request tracing](observability.md).

`/metrics` has no authentication. To keep it away from the clients that reach `-listen`, bind `-metrics-listen` to an address only your monitoring can reach, such as `127.0.0.1:9090` or an internal interface.

### `-public-url`

The base URL clients use to reach pkgwarden, such as `https://pkgwarden.example.com`. pkgwarden writes it into the absolute links it serves:

- npm `dist.tarball` URLs in packuments and version manifests.
- PyPI file links on simple pages, and the redirect target for a non-normalized project name.
- The `dl` URL in Cargo's `/cargo/index/config.json`.

A trailing `/` is removed. pkgwarden does not validate the value.

When `-public-url` is empty, pkgwarden builds the base URL from each request. It takes the host from the `Host` header. It takes the scheme from `X-Forwarded-Proto` when that header is `http` or `https`, and otherwise uses `https` for a TLS connection and `http` for the rest. It ignores `X-Forwarded-Host`. The RubyGems and Go protocols carry no absolute links, so the setting does not affect them.

### `-log-level`

The lowest level that reaches the log. Use `debug`, `info`, `warn`, or `error`. Case does not matter. Any other value stops pkgwarden at startup with exit status 2. pkgwarden writes JSON lines to stderr. At `info`, it logs one `request` line per request and one `upstream` line per outbound call. `debug` adds the cache lines that explain a missing `upstream` line, and the `request` lines for `/healthz` and `/metrics`. See [Read the logs](deployment.md#read-the-logs).

### `-metadata-ttl`

How long pkgwarden caches each upstream metadata document, such as a packument, an index file, a version list, or a download count. The cache holds at most 512 documents. `0` or a negative value turns the cache off, but concurrent requests for one document still share one upstream request.

## Policy flags

### `-cooldown`

The minimum age a release must reach before pkgwarden serves it. `0` turns the cooldown off. A negative value is rejected. See [Cooldown](cooldown.md).

### `-block-severity`

The lowest vulnerability rating that blocks a release. Use `low`, `medium`, `high`, `critical`, or `none`, in any case. Lower-rated and unrated vulnerabilities only warn. `none` never blocks for a vulnerability. Malicious releases block at every value. See [The severity threshold](advisories.md#the-severity-threshold).

### `-fail-open`

When an advisory source fails, pkgwarden blocks the package by default. With `-fail-open`, it serves the package with an `advisory-lookup` warning instead. See [When a lookup fails](advisories.md#when-a-lookup-fails).

### `-allow`

A comma-separated list of `ecosystem:name` entries, such as `npm:my-internal-lib,pypi:internal-tools,go:github.com/acme/lib`. An allowlisted package skips the cooldown, the advisory lookup, and the heuristics. Its verdict carries one finding with rule `allowlist` and decision `allow`.

The ecosystem is one of `npm`, `pypi`, `rubygems`, `go`, or `cargo`, in any case. pkgwarden compares names after the ecosystem's normalization:

| Ecosystem | Name comparison |
| --- | --- |
| npm | Case-insensitive. |
| PyPI | PEP 503. Case and runs of `-`, `_`, and `.` do not matter. |
| RubyGems | Exact. |
| Go | Exact module path. |
| Cargo | Case-insensitive, and `_` equals `-`. |

Spaces around an entry are ignored, and empty entries are skipped. The allowlist does not cover versions that upstream does not publish. A request for such a version still gets an `unknown-release` block.

## Heuristics flags

See [Heuristics](heuristics.md) for what each signal does.

### `-heuristics`

Turns the heuristic signals on or off. `-heuristics=false` turns them all off.

### `-heuristics-warn`

The score at which a release is served with a warning. `0` or less turns warnings off. It must not exceed `-heuristics-block`.

### `-heuristics-block`

The score at which a release is blocked. The highest possible score is 155, so a value above 155 never blocks. `0` or less also never blocks.

### `-new-package-age`

A package first published less than this long ago fires `heuristic/new-package`. `0` turns the signal off.

### `-low-downloads`

A package with fewer weekly downloads than this fires `heuristic/low-downloads`. `0` turns the signal off. The signal never fires for Go, which has no download counts.

## Advisory source flags

See [Advisories](advisories.md) for how the sources are used.

### `-osv-url`

The base URL of the OSV API. pkgwarden sends `POST <osv-url>/v1/query`. A trailing `/` is removed. Any server that implements that endpoint works.

### `-ghsa-token`

A GitHub token. When it is set, pkgwarden also queries the GitHub Advisory Database at `https://api.github.com/advisories` and sends the token as a bearer token. When neither the flag nor `PKGWARDEN_GHSA_TOKEN` is set, pkgwarden uses the value of `GITHUB_TOKEN` at startup. An empty value, such as `-ghsa-token ''`, turns the source off, even when `GITHUB_TOKEN` is set. The help text names `$GITHUB_TOKEN` as the default but never prints a token.

### `-openssf`

Downloads the OpenSSF malicious-packages dataset in the background and checks every package against it. Each refresh downloads about 300 MB. Until the first download finishes, every package is blocked with `advisory-lookup`, unless `-fail-open` is set. See [The OpenSSF dataset](advisories.md#the-openssf-dataset).

### `-openssf-refresh`

How often pkgwarden downloads the OpenSSF dataset again. After a failed download, pkgwarden retries after 30 seconds and doubles the wait after each further failure, up to `-openssf-refresh`. `0` or a negative value loads it once and never refreshes it, even when that one load fails.

### `-advisory-ttl`

How long pkgwarden caches the merged advisory result for one package. The cache holds at most 10000 packages. Failed lookups are never cached. `0` or a negative value turns the cache off.

## Startup errors

pkgwarden checks its configuration before it listens. Each error below was captured from the binary built at the current commit.

| Input | Message on stderr | Exit status |
| --- | --- | --- |
| `-bogus` | `flag provided but not defined: -bogus`, the help text, then `pkgwarden: flag provided but not defined: -bogus` | 2 |
| `-cooldown 7d` | `invalid value "7d" for flag -cooldown: parse error`, the help text, then `pkgwarden: invalid value "7d" for flag -cooldown: parse error` | 2 |
| `PKGWARDEN_COOLDOWN=abc` | `pkgwarden: PKGWARDEN_COOLDOWN: parse error` | 2 |
| `-cooldown -1s` | `pkgwarden: -cooldown must not be negative` | 2 |
| `-heuristics-warn 80` | `pkgwarden: -heuristics-warn (80) must not exceed -heuristics-block (70)` | 2 |
| `-allow foo` | `pkgwarden: -allow entry "foo": want ecosystem:name` | 2 |
| `-allow npm:` | `pkgwarden: -allow entry "npm:": want ecosystem:name` | 2 |
| `-allow maven:x` | `pkgwarden: -allow entry "maven:x": unknown ecosystem "maven"` | 2 |
| `-block-severity moderate` | `pkgwarden: -block-severity "moderate": want low, medium, high, critical or none` | 2 |
| `-log-level verbose` | `invalid value "verbose" for flag -log-level: slog: level string "verbose": unknown name`, the help text, then `pkgwarden: invalid value "verbose" for flag -log-level: slog: level string "verbose": unknown name` | 2 |
| `PKGWARDEN_LOG_LEVEL=verbose` | `pkgwarden: PKGWARDEN_LOG_LEVEL: slog: level string "verbose": unknown name` | 2 |
| A `-listen` address already in use | `{"time":"...","level":"ERROR","msg":"exiting","err":"listen tcp 127.0.0.1:18181: bind: address already in use"}` | 1 |

A bind error comes after the configuration checks, so it is a JSON log line with exit status 1. pkgwarden does not log `listening` in that case.

## Example configurations

Each example below starts cleanly with the binary built at the current commit.

### Strict

Wait two weeks, block medium vulnerabilities, check GitHub and OpenSSF directly, and block on a lower heuristic score:

	export GITHUB_TOKEN=<your token>
	pkgwarden \
		-cooldown 336h \
		-block-severity medium \
		-openssf \
		-heuristics-warn 20 \
		-heuristics-block 50

With these thresholds, `new-package` plus `low-downloads` blocks, and a `typosquat` match blocks on its own. Every install is blocked until the OpenSSF dataset loads, which took about 11 seconds in one test.

### Lenient

Wait one day, block only critical vulnerabilities, keep serving when OSV is down, and let heuristics warn without blocking:

	pkgwarden \
		-cooldown 24h \
		-block-severity critical \
		-fail-open \
		-heuristics-block 1000

Malicious releases still block with these settings.

### Container with environment variables

	docker run -p 8080:8080 \
		-e PKGWARDEN_COOLDOWN=72h \
		-e PKGWARDEN_ALLOW=npm:my-internal-lib,pypi:internal-tools \
		-e PKGWARDEN_PUBLIC_URL=https://pkgwarden.example.com \
		-e GITHUB_TOKEN \
		pkgwarden

`-e GITHUB_TOKEN` with no value passes the variable from your shell into the container.

### Restricted networks

pkgwarden cannot run air-gapped. It fetches every metadata document, every artifact, and every advisory from the public internet at request time, and it stores nothing on disk. What you can restrict is the client side, so that clients reach only pkgwarden and pkgwarden alone reaches the internet.

- Allow pkgwarden's egress to the hosts in [Allow outbound traffic](deployment.md#allow-outbound-traffic).
- To keep advisory traffic inside your network, run an OSV-compatible server and point `-osv-url` at it. Leave `-ghsa-token` empty and `-openssf` off, since both always call GitHub.
- Go clients still need `sum.golang.org` unless you set `GOSUMDB=off` or list the modules in `GONOSUMDB`. See [Go](package-managers.md#go).
- Leave `-fail-open` off if a silent gap in advisory coverage is worse for you than a failed install.
