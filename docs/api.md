# HTTP API reference

pkgwarden serves one HTTP listener, or two with `-metrics-listen`. It mounts one adapter per ecosystem, a check endpoint, a health endpoint, and the metrics endpoint. The top-level routes are defined in `internal/proxy/server.go`, and `/metrics` is added in `cmd/pkgwarden/main.go`.

## Top-level routes

| Path | Serves |
| --- | --- |
| `/npm/` | The npm registry protocol. |
| `/pypi/` | The PyPI simple repository API and distribution files. |
| `/rubygems/` | The RubyGems compact index, gem downloads, and the other RubyGems endpoints. |
| `/go/` | The Go module proxy protocol. |
| `/cargo/` | The Cargo sparse index and crate downloads. |
| `/api/v1/check` | The verdict for a package or a release. |
| `/healthz` | A liveness check. |
| `/metrics` | Prometheus metrics. Served here unless `-metrics-listen` is set. |

Any other path answers 404. With `-metrics-listen`, the second listener serves only `/metrics` and answers 404 for every other path.

## `GET /api/v1/check`

Returns the verdict for a package, or for one release of it, without downloading anything. It answers `GET` and `HEAD`. Any other method gets 405 with `Allow: GET, HEAD`.

### Parameters

| Parameter | Required | Value |
| --- | --- | --- |
| `ecosystem` | Yes | `npm`, `pypi`, `rubygems`, `go`, or `cargo`, in any case. |
| `name` | Yes | The package name as the registry spells it. A scoped npm name such as `@types/node` and a Go module path such as `golang.org/x/text` go in as they are. |
| `version` | No | One version. Without it, the response holds the package verdict only. |

### Response

The status is 200 and the body is indented JSON.

| Field | Type | Meaning |
| --- | --- | --- |
| `ecosystem` | string | The ecosystem, in lower case. |
| `name` | string | The package name. PyPI returns the PEP 503 normalized name. Cargo returns the crate's canonical name from crates.io. The other ecosystems return the name you sent. |
| `version` | string | The version you sent. Left out when you sent none. |
| `decision` | string | `allow`, `warn`, or `block`. It is the strictest decision among the findings, or `allow` when there are none. |
| `findings` | array | Every finding behind the verdict, including ones less strict than `decision`. Left out when empty. |
| `findings[].rule` | string | The rule that produced the finding. See [Rules](#rules). |
| `findings[].decision` | string | `allow`, `warn`, or `block`. |
| `findings[].reason` | string | A sentence that explains the finding. |

Without `version`, the response holds only findings that apply to every release. A package can report `allow` while every one of its releases is blocked. Ask for a version to see its verdict.

With `version`, the response merges the package findings with the release's own findings. A version that upstream does not report gets an `unknown-release` block.

This response was captured on 2026-11-07:

	$ curl -s 'http://127.0.0.1:18181/api/v1/check?ecosystem=pypi&name=requests&version=2.31.0'
	{
	  "ecosystem": "pypi",
	  "name": "requests",
	  "version": "2.31.0",
	  "decision": "warn",
	  "findings": [
	    {
	      "rule": "advisory/vulnerability",
	      "decision": "warn",
	      "reason": "GHSA-9hjg-9r4m-mvj7 (medium vulnerability, via osv): Requests vulnerable to .netrc credentials leak via malicious URLs https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7"
	    },
	    {
	      "rule": "advisory/vulnerability",
	      "decision": "warn",
	      "reason": "GHSA-9wx4-h78v-vm56 (medium vulnerability, via osv): Requests `Session` object does not verify requests after making first request with verify=False https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56"
	    },
	    {
	      "rule": "advisory/vulnerability",
	      "decision": "warn",
	      "reason": "GHSA-gc5v-m9x4-r6x2 (medium vulnerability, via osv): Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2"
	    }
	  ]
	}

A package with no findings returns only the first fields:

	$ curl -s 'http://127.0.0.1:18181/api/v1/check?ecosystem=npm&name=lodash'
	{
	  "ecosystem": "npm",
	  "name": "lodash",
	  "decision": "allow"
	}

### Errors

Error bodies are plain text.

| Status | Body | Cause |
| --- | --- | --- |
| 400 | `unknown ecosystem "maven"` | `ecosystem` is missing or not one of the five. |
| 400 | `ecosystem not enabled or name missing` | `name` is missing. |
| 404 | `not found` | The upstream registry has no such package. |
| 502 | `upstream error: <error>` | The upstream registry failed or answered with an unexpected status. |

A failed advisory lookup is not an error. It is an `advisory-lookup` finding in a 200 response.

### Rules

These are the `Rule` constants in `internal/policy/policy.go`. There are 12. To count them, run `grep -c 'Rule = "' internal/policy/policy.go`.

| Rule | Decisions | Applies to | Meaning |
| --- | --- | --- | --- |
| `allowlist` | `allow` | Package | The package is on `-allow`. No other check ran. |
| `cooldown` | `block` | Release | The release is younger than `-cooldown`, or its publish time is unknown. See [Cooldown](cooldown.md). |
| `advisory/malicious` | `block` | Release, or package for a package-wide advisory | An advisory reports the release as malicious. See [Advisories](advisories.md). |
| `advisory/vulnerability` | `warn`, `block` | Release, or package for a package-wide advisory | A vulnerability advisory covers the release. It blocks at `-block-severity` or above. See [The severity threshold](advisories.md#the-severity-threshold). |
| `advisory-lookup` | `warn`, `block` | Package | An advisory source failed. `block` by default, `warn` with `-fail-open`. |
| `heuristic/new-package` | `warn`, `block` | Package, restated on a release | The package is younger than `-new-package-age`. |
| `heuristic/low-downloads` | `warn`, `block` | Package, restated on a release | Weekly downloads are below `-low-downloads`. |
| `heuristic/typosquat` | `warn`, `block` | Package, restated on a release | The name resembles a popular package. |
| `heuristic/maintainer-change` | `warn`, `block` | Release | The release names a publisher who published no earlier release. |
| `heuristic/install-scripts` | `warn`, `block` | Release | The release adds npm install scripts. |
| `heuristic/score` | `warn`, `block` | Package or release | The sum of the heuristic signals and the threshold it reached. |
| `unknown-release` | `block` | Release | Upstream does not publish the requested version. |

[Where heuristic findings appear](heuristics.md#where-heuristic-findings-appear) explains when a package signal is restated on a release.

## `GET /healthz`

Returns status 200 with the body `ok` and a newline. It answers `GET` and `HEAD`. It does not contact any upstream or advisory source, so it reports only that the process is serving.

## `GET /metrics`

Returns every metric in the Prometheus exposition format. It answers `GET` and `HEAD`, and any other method gets 405. [Metrics and request tracing](observability.md#metric-reference) lists the metrics.

## Response headers

Every response carries `X-Request-Id`, the ID of the request. pkgwarden keeps an `X-Request-Id` sent with the request when it is 1 to 64 characters, each a letter, a digit, `.`, `_`, or `-`. Otherwise it generates 32 lowercase hexadecimal digits. Every log line about the request carries the same ID as `request_id`. See [Follow one request through the logs](observability.md#follow-one-request-through-the-logs).

pkgwarden adds these headers to every response that went through the policy. Those are the metadata documents and the files listed in [Ecosystem routes](#ecosystem-routes) as filtered or enforced. Responses that pkgwarden passes through unchanged carry neither header.

| Header | Value |
| --- | --- |
| `X-Pkgwarden-Decision` | `allow`, `warn`, or `block`. On a metadata document it is the package verdict. On a file it is the release verdict. |
| `X-Pkgwarden-Warning` | Sent only when the decision is `warn`. It joins every `warn` finding as `<rule>: <reason>`, separated by `; `. Its length is not capped. |

This header pair was captured on 2026-11-07 from a download of `requests-2.31.0-py3-none-any.whl`:

	X-Pkgwarden-Decision: warn
	X-Pkgwarden-Warning: advisory/vulnerability: GHSA-9hjg-9r4m-mvj7 (medium vulnerability, via osv): Requests vulnerable to .netrc credentials leak via malicious URLs https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7; advisory/vulnerability: GHSA-9wx4-h78v-vm56 (medium vulnerability, via osv): Requests `Session` object does not verify requests after making first request with verify=False https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56; advisory/vulnerability: GHSA-gc5v-m9x4-r6x2 (medium vulnerability, via osv): Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2

## The 403 response

A blocked request gets status 403, `X-Pkgwarden-Decision: block`, and `X-Content-Type-Options: nosniff`. The body depends on the ecosystem.

| Ecosystem | `Content-Type` | Body |
| --- | --- | --- |
| npm | `application/json` | `{"error":"<message>"}` and a newline. npm prints the `error` field. |
| PyPI, RubyGems, Go, Cargo | `text/plain; charset=utf-8` | `<message>` and a newline. |

The message has this form:

	pkgwarden blocked <subject>: <rule>: <reason>; <rule>: <reason> (request <id>)

The subject is `<ecosystem>/<name>` for a package-level block and `<ecosystem>/<name>@<version>` for a release. The message lists only the findings whose decision is `block`. It ends with the request ID, so whoever reads the logs can find the request. See [Follow one request through the logs](observability.md#follow-one-request-through-the-logs).

pkgwarden keeps the message short, because the go command replaces a longer body with `[Truncated: too long.]`.

- Each `<rule>: <reason>` part longer than 160 bytes is cut to 157 bytes and ends with `...`.
- When the next part would take the message past 540 bytes less the length of the ` (request <id>)` suffix, pkgwarden stops and appends `and <N> more, see /api/v1/check`. N counts the `block` findings not yet listed. It leaves out `warn` findings, which the message never lists.

This body was captured on 2026-11-07:

	$ curl -s http://127.0.0.1:18181/rubygems/gems/rack-2.2.3.gem
	pkgwarden blocked rubygems/rack@2.2.3: advisory/vulnerability: GHSA-3h57-hmj3-gj3p (high vulnerability, via osv): Rack has possible DoS Vulnerability in Multipart MIME parsing https://osv.dev/vuln...; advisory/vulnerability: GHSA-625h-95r8-8xpm (high vulnerability, via osv): Rack has an unsafe default in Rack::QueryParser allows params_limit bypass via sem...; and 13 more, see /api/v1/check (request 997f78977a78ee1429e39fcd9e0477f7)

The full verdict for that release had 32 findings, 15 of them `block`. The message lists 2, so N is 13.

## Ecosystem routes

Each table lists the routes an adapter handles, relative to the server root. Filtered means pkgwarden rewrites the upstream document. Enforced means pkgwarden checks the verdict before it streams the upstream response. Passed through means pkgwarden relays the upstream response without a policy check.

When an upstream request fails, every adapter answers 404 with `not found` for a missing resource, and 502 with `upstream error: <error>` otherwise.

### npm

The upstream is `https://registry.npmjs.org`. Download counts come from `https://api.npmjs.org`.

| Route | Handling |
| --- | --- |
| `GET /npm/<name>`, `GET /npm/@<scope>/<name>` | Filtered packument. `@scope%2fname` also works. |
| `GET /npm/<name>/<version-or-tag>` | One version manifest from the filtered packument. A missing version gets the 403 for that version. A dist-tag that filtering removed gets the 403 for the version the tag points at upstream. |
| `GET /npm/<name>/-/<file>.tgz` | Enforced tarball. The version comes from the file name. |
| `POST /npm/-/npm/v1/security/advisories/bulk`, `POST /npm/-/npm/v1/security/audits/quick` | Passed through, for `npm audit`. |
| Any other `GET` | Passed through, with only the `Accept` header and the query string. |
| Any other method | 405. |

### PyPI

The upstream is `https://pypi.org`. Files come from `https://files.pythonhosted.org`. Download counts come from `https://pypistats.org`.

| Route | Handling |
| --- | --- |
| `GET /pypi/simple/` | Passed through. The links on that page point at `/simple/<project>/` on the server root, so they do not work through pkgwarden. |
| `GET /pypi/simple/<project>/` | Filtered project page, built from `https://pypi.org/pypi/<project>/json`. PEP 691 JSON or PEP 503 HTML, chosen by `Accept`. |
| `GET /pypi/simple/<project>` or a non-normalized name | 301 to `/pypi/simple/<normalized>/`. |
| `GET /pypi/files/<project>/<version>/<filename>` | Enforced file. Also serves `<filename>.metadata` for PEP 658. `Range` is forwarded. |

The file route never takes a URL from the client. pkgwarden looks the file name up in the project's metadata and serves it only from a URL under `https://files.pythonhosted.org/`. A file name the release does not have gets 404.

### RubyGems

The upstream is `https://rubygems.org`.

| Route | Handling |
| --- | --- |
| `GET /rubygems/info/<gem>` | Filtered compact index file. A gem blocked at package level gets a body of `---` and status 200. |
| `GET /rubygems/gems/<file>.gem` | Enforced download. |
| `GET /rubygems/quick/Marshal.4.8/<file>.gemspec.rz` | Enforced gemspec. |
| Any other `GET`, including `/rubygems/versions`, `/rubygems/names`, and `/rubygems/specs.4.8.gz` | Passed through, with `Range`, `If-None-Match`, `If-Modified-Since`, `Accept-Encoding`, and the query string. |

The filtered info file keeps every surviving line byte for byte. Its `ETag` is the MD5 of the filtered body, and its `Repr-Digest` is the SHA-256 of the filtered body. It answers a matching `If-None-Match` with 304. It ignores `Range` and always sends the whole file.

A download file name must match an uploaded version and platform exactly, such as `nokogiri-1.16.0-x86_64-linux.gem`. Otherwise the request gets 404.

### Go

The upstream is `https://proxy.golang.org`. The routes use the escaped module path, such as `github.com/!burnt!sushi/toml`.

| Route | Handling |
| --- | --- |
| `GET /go/<module>/@v/list` | Filtered version list. |
| `GET /go/<module>/@latest` | The `.info` of the newest allowed release, or of the newest allowed prerelease when no release is allowed. |
| `GET /go/<module>/@v/<version>.info`, `GET /go/<module>/@v/<version>.mod` | Passed through for every version, because minimal version selection reads the `go.mod` of versions it will not select. |
| `GET /go/<module>/@v/<version>.zip` | Enforced. The version must be canonical, or the request gets 400. A pseudo-version that the list does not include is fetched and assessed too. |
| `GET /go/sumdb/<path>` | Passed through. `proxy.golang.org` answers 404, so the go command contacts `sum.golang.org` directly. |
| Any other path | 400 with `bad request: <error>`. |
| Any method but `GET` | 405, including `HEAD`. |

### Cargo

The index comes from `https://index.crates.io`. Crate metadata comes from `https://crates.io/api/v1/crates/<crate>`. Files come from `https://static.crates.io/crates`.

| Route | Handling |
| --- | --- |
| `GET /cargo/index/config.json` | Generated. `dl` is `<public URL>/cargo/api/v1/crates`, and `api` is `https://crates.io`. |
| `GET /cargo/index/<prefix>/<crate>` | Filtered index file. Surviving lines are kept byte for byte. |
| `GET /cargo/api/v1/crates/<crate>/<version>/download` | Enforced download. |

pkgwarden checks an index path before it contacts upstream. The crate name must be lower case, at most 64 characters of `a` to `z`, `0` to `9`, `-`, and `_`, and the prefix must be the one Cargo derives from it. Any other path gets 404. A download whose file `static.crates.io` does not have gets 404, although `static.crates.io` itself answers 403 for a missing file.
