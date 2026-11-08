# Metrics and request tracing

pkgwarden exports Prometheus metrics at `/metrics`, and it gives every inbound request an ID that appears on every log line about that request. The first half of this page is a reference of every metric. The second half shows how to follow one request through the logs. The collectors are defined in `internal/telemetry/metrics.go`.

## Where `/metrics` is served

By default, pkgwarden serves `GET /metrics` on the `-listen` address, next to `/healthz`. With [`-metrics-listen`](configuration.md#-metrics-listen) set, pkgwarden serves `/metrics` only on that address, and the main listener answers 404 for `/metrics`.

`/metrics` has no authentication, like every other route. Anyone who can reach the port can read the metrics. To keep scrapes off the port that package managers use, set `-metrics-listen` to an address that only your Prometheus server can reach. [Scrape it with Prometheus](deployment.md#scrape-it-with-prometheus) has a scrape configuration.

## Metric reference

Every pkgwarden series starts with `pkgwarden_`. No metric has a package name or version label, because those would create one series per package. Per-package detail is in the logs. `/metrics` also carries the standard `go_` and `process_` series of the Prometheus Go client.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `pkgwarden_http_requests_total` | counter | `ecosystem`, `method`, `code` | Inbound requests that pkgwarden answered. |
| `pkgwarden_http_request_duration_seconds` | histogram | `ecosystem` | Time from the request's arrival until pkgwarden finished the response. |
| `pkgwarden_decisions_total` | counter | `ecosystem`, `stage`, `decision` | Policy verdicts that pkgwarden applied to a response. |
| `pkgwarden_findings_total` | counter | `ecosystem`, `stage`, `rule`, `decision` | Rules behind each `warn` or `block` verdict. |
| `pkgwarden_artifacts_served_total` | counter | `ecosystem` | Package files that pkgwarden relayed to a client. |
| `pkgwarden_artifact_bytes_total` | counter | `ecosystem` | Bytes of those package files. |
| `pkgwarden_upstream_requests_total` | counter | `host`, `code` | Outbound requests to registries and advisory sources. |
| `pkgwarden_upstream_request_duration_seconds` | histogram | `host` | Time from sending an outbound request until its response headers arrived. |
| `pkgwarden_cache_requests_total` | counter | `cache`, `result` | Lookups in the metadata cache and the advisory cache. |
| `pkgwarden_openssf_last_success_timestamp_seconds` | gauge | none | Unix time of the last successful OpenSSF dataset load. `0` until the first load, and always `0` without `-openssf`. |
| `pkgwarden_openssf_packages` | gauge | none | Packages in the loaded OpenSSF index. |
| `pkgwarden_openssf_refresh_failures_total` | counter | none | Failed OpenSSF dataset refreshes. A refresh cut short by shutdown is not counted. |
| `pkgwarden_policy_info` | gauge | `cooldown`, `block_severity`, `fail_open`, `heuristics`, `heuristics_warn`, `heuristics_block` | Always `1`. The labels hold the policy flags the process started with. |
| `pkgwarden_build_info` | gauge | `version`, `go_version` | Always `1`. `version` is the `VERSION` build argument for an image built by the `Dockerfile`, or `(devel)` when the build sets none. A binary built by `go build` or `go run` reports the module version from the Go build information, such as `v0.0.0-20261107233310-f009d03e5c9d`. |

The histograms use these bucket bounds in seconds: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, and 60.

### Label values

| Label | Values |
| --- | --- |
| `ecosystem` on `http_` metrics | `npm`, `pypi`, `rubygems`, `go`, or `cargo` for the adapter routes, `api` for `/api/`, and `other` for every other path, including `/healthz` and `/metrics`. |
| `ecosystem` on the other metrics | `npm`, `pypi`, `rubygems`, `go`, or `cargo`. |
| `method` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `CONNECT`, or `TRACE`. Any other method is `other`. |
| `code` on `http_requests_total` | The response status, such as `200` or `403`. |
| `code` on `upstream_requests_total` | The upstream status, or `error` when no response arrived, such as after a timeout or a refused connection. |
| `host` | The host and port of the outbound URL, such as `registry.npmjs.org`. Each redirect hop counts as its own request to its own host. |
| `stage` | `metadata` for a package document: a packument or version manifest, a simple index page, a compact index file, a Go version list or `@latest`, or a sparse index file. `artifact` for a request for one release's file. |
| `decision` | `allow`, `warn`, or `block`. |
| `rule` | A rule name from [Rules](api.md#rules), such as `advisory/malicious` or `cooldown`. |
| `cache` | `metadata` or `advisory`. |
| `result` | `hit` or `miss`. |

### What each counter counts

`pkgwarden_decisions_total` counts one verdict each time pkgwarden applies one. Most requests apply one verdict. Three metadata paths apply two: the package verdict first, then the verdict of one version. They are an npm packument whose versions are all blocked, an npm version manifest for a blocked version, and a Go `@latest` with no allowed version. The RubyGems info file of a gem blocked at package level counts as a `metadata` `block`, although it answers 200 with an empty index.

`pkgwarden_findings_total` counts each rule once per verdict, however many findings that rule produced. For a `block`, it counts only the rules whose findings block. For a `warn`, it counts the rules whose findings warn. An `allow` adds nothing. A release blocked by two vulnerabilities and the cooldown adds 1 to `advisory/vulnerability` and 1 to `cooldown`.

`pkgwarden_artifacts_served_total` counts an npm tarball, a Python distribution file, a `.gem` file, a Go module `.zip`, or a `.crate` file when upstream answered 200 or 206. A 206 range response counts as one file, so a client that resumes a download in parts counts more than once. PEP 658 `.metadata` files, RubyGems gemspecs, `HEAD` requests, and files that pkgwarden passes through without a policy check are not counted. `pkgwarden_artifact_bytes_total` adds the bytes that pkgwarden copied to the client, which is less than the file size when the client disconnects early.

`pkgwarden_cache_requests_total` counts a `miss` for every metadata or advisory lookup that the cache could not answer, including one that then shares another request's upstream call.

### Example queries

Each query answers one question a security engineer asks about a running proxy.

| Question | PromQL |
| --- | --- |
| How many requests does each ecosystem get? | `sum by (ecosystem) (rate(pkgwarden_http_requests_total[5m]))` |
| How slow is each ecosystem for clients? | `histogram_quantile(0.95, sum by (ecosystem, le) (rate(pkgwarden_http_request_duration_seconds_bucket[5m])))` |
| How many downloads did pkgwarden block in the last day? | `sum by (ecosystem) (increase(pkgwarden_decisions_total{stage="artifact", decision="block"}[24h]))` |
| How many malicious-package blocks happened in the last day? | `sum by (ecosystem) (increase(pkgwarden_findings_total{rule="advisory/malicious", decision="block"}[24h]))` |
| Is a typosquat campaign under way? | `sum by (ecosystem) (increase(pkgwarden_findings_total{rule="heuristic/typosquat"}[1h]))` |
| Is the cooldown holding back new releases? | `sum by (ecosystem) (increase(pkgwarden_findings_total{rule="cooldown"}[24h]))` |
| Are advisory lookups failing, so that packages are blocked or served unchecked? | `sum(increase(pkgwarden_findings_total{rule="advisory-lookup"}[15m])) > 0` |
| How many package files went out, and how much data? | `sum by (ecosystem) (increase(pkgwarden_artifacts_served_total[24h]))` and `sum by (ecosystem) (increase(pkgwarden_artifact_bytes_total[24h]))` |
| Which upstream host is failing? | `sum by (host) (rate(pkgwarden_upstream_requests_total{code=~"error\|5.."}[5m])) / sum by (host) (rate(pkgwarden_upstream_requests_total[5m]))` |
| Is a registry rate-limiting pkgwarden? | `sum by (host) (rate(pkgwarden_upstream_requests_total{code="429"}[5m]))` |
| How slow is each upstream? | `histogram_quantile(0.95, sum by (host, le) (rate(pkgwarden_upstream_request_duration_seconds_bucket[5m])))` |
| How often do the caches answer? | `sum by (cache) (rate(pkgwarden_cache_requests_total{result="hit"}[1h])) / sum by (cache) (rate(pkgwarden_cache_requests_total[1h]))` |
| Is the OpenSSF index older than 12 hours? Use only on instances with `-openssf`. | `time() - pkgwarden_openssf_last_success_timestamp_seconds > 12 * 3600` |
| Did the OpenSSF index shrink? | `delta(pkgwarden_openssf_packages[1d]) < 0` |
| Are OpenSSF refreshes failing? | `increase(pkgwarden_openssf_refresh_failures_total[1h]) > 0` |
| Which instances serve unchecked packages when advisories fail? | `pkgwarden_policy_info{fail_open="true"}` |
| Which instances run a cooldown other than 7 days? | `pkgwarden_policy_info{cooldown!="168h0m0s"}` |
| Which versions are running? | `count by (version) (pkgwarden_build_info)` |

This excerpt of `/metrics` was captured on 2026-11-07, after a few requests to a fresh instance. It keeps only some of the `pkgwarden_` series:

	pkgwarden_artifact_bytes_total{ecosystem="npm"} 2967
	pkgwarden_artifacts_served_total{ecosystem="npm"} 1
	pkgwarden_cache_requests_total{cache="advisory",result="hit"} 4
	pkgwarden_cache_requests_total{cache="metadata",result="hit"} 9
	pkgwarden_decisions_total{decision="block",ecosystem="npm",stage="artifact"} 2
	pkgwarden_decisions_total{decision="block",ecosystem="rubygems",stage="metadata"} 1
	pkgwarden_decisions_total{decision="warn",ecosystem="pypi",stage="artifact"} 1
	pkgwarden_findings_total{decision="block",ecosystem="npm",rule="advisory/vulnerability",stage="artifact"} 2
	pkgwarden_findings_total{decision="block",ecosystem="rubygems",rule="heuristic/typosquat",stage="metadata"} 1
	pkgwarden_http_requests_total{code="403",ecosystem="npm",method="GET"} 2
	pkgwarden_policy_info{block_severity="high",cooldown="168h0m0s",fail_open="false",heuristics="true",heuristics_block="70",heuristics_warn="30"} 1
	pkgwarden_upstream_requests_total{code="200",host="api.osv.dev"} 7

## Follow one request through the logs

Every inbound request gets a request ID. pkgwarden returns it in the `X-Request-Id` response header and adds it as `request_id` to every log line about the request. That covers the `request` line for the inbound request, an `upstream` line for each call to a registry or advisory source, and the `blocked` or `serving with warnings` line. The ID never goes upstream. [Read the logs](deployment.md#read-the-logs) lists every message and its fields.

1. Find the request ID. Use one of these sources:

	- The `X-Request-Id` header of the response.
	- The end of a 403 body, which reads `(request <id>)`. npm and the go command print that body, so a developer can copy the ID from the error. pip and gem print only the status. See [Point your package managers at pkgwarden](package-managers.md).
	- An ID you chose and sent in the request. See [Send your own request ID](#send-your-own-request-id).

2. Select the log lines with that ID:

		grep '"request_id":"44a4852c6967cc178eeb041d5148228e"' pkgwarden.log

	With jq, select on the field instead:

		jq -c 'select(.request_id == "44a4852c6967cc178eeb041d5148228e")' pkgwarden.log

3. Read the lines in order. The `upstream` lines come first, because pkgwarden writes the `request` line when it finishes the response. An `upstream` line logs the method, host, path without the query, status, `content_length` when upstream sent one, and `duration_ms` until the response headers arrived. It never logs a header value, so the GitHub token stays out of the log.

This trace of a blocked download was captured on 2026-11-07. npm printed the 403 body, which ends with the ID:

	npm error 403 403 Forbidden - GET http://127.0.0.1:18181/npm/lodash/-/lodash-4.17.20.tgz - pkgwarden blocked npm/lodash@4.17.20: advisory/vulnerability: GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): ... (request 0d43614cae40e59f3c498ff91116a7be)

The same download made with curl got the ID `44a4852c6967cc178eeb041d5148228e`. These are its log lines, with the long `reasons` field trimmed:

	{"time":"2026-11-07T18:36:28.958115-05:00","level":"INFO","msg":"upstream","request_id":"44a4852c6967cc178eeb041d5148228e","method":"GET","host":"registry.npmjs.org","path":"/lodash","status":200,"duration_ms":42.187}
	{"time":"2026-11-07T18:36:28.96364-05:00","level":"INFO","msg":"upstream","request_id":"44a4852c6967cc178eeb041d5148228e","method":"GET","host":"api.npmjs.org","path":"/downloads/point/last-week/lodash","status":200,"duration_ms":47.68}
	{"time":"2026-11-07T18:36:29.153123-05:00","level":"INFO","msg":"upstream","request_id":"44a4852c6967cc178eeb041d5148228e","method":"POST","host":"api.osv.dev","path":"/v1/query","status":200,"content_length":43381,"duration_ms":162.179}
	{"time":"2026-11-07T18:36:29.188059-05:00","level":"INFO","msg":"blocked","request_id":"44a4852c6967cc178eeb041d5148228e","ecosystem":"npm","package":"lodash","version":"4.17.20","stage":"artifact","rules":["advisory/vulnerability"],"reasons":"advisory/vulnerability: GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash ..."}
	{"time":"2026-11-07T18:36:29.18813-05:00","level":"INFO","msg":"request","request_id":"44a4852c6967cc178eeb041d5148228e","method":"GET","path":"/npm/lodash/-/lodash-4.17.20.tgz","status":403,"bytes":408,"duration_ms":272.287,"ecosystem":"npm","decision":"block","user_agent":"curl/8.7.1","remote_addr":"127.0.0.1:55977"}

pkgwarden fetched the packument and the download count from npm and queried OSV, and it never contacted the tarball host. An allowed download has one more `upstream` line, for the file itself.

### Explain a missing upstream line

A request answered from the cache makes no upstream call, so its trace has no `upstream` line for that document. With `-log-level debug`, pkgwarden logs `metadata cache hit` with the URL, and `advisory cache hit` with the ecosystem and package. These lines were captured on 2026-11-07 from the second of two requests for `/pypi/simple/requests/`:

	{"time":"2026-11-07T18:36:29.955285-05:00","level":"DEBUG","msg":"metadata cache hit","request_id":"5a6fc2cf9c15c824ced7d78d62b1fc4d","url":"https://pypi.org/pypi/requests/json"}
	{"time":"2026-11-07T18:36:29.956086-05:00","level":"DEBUG","msg":"metadata cache hit","request_id":"5a6fc2cf9c15c824ced7d78d62b1fc4d","url":"https://pypistats.org/api/packages/requests/recent"}
	{"time":"2026-11-07T18:36:29.956139-05:00","level":"DEBUG","msg":"advisory cache hit","request_id":"5a6fc2cf9c15c824ced7d78d62b1fc4d","ecosystem":"pypi","package":"requests"}
	{"time":"2026-11-07T18:36:30.060024-05:00","level":"INFO","msg":"request","request_id":"5a6fc2cf9c15c824ced7d78d62b1fc4d","method":"GET","path":"/pypi/simple/requests/","status":200,"bytes":21021,"duration_ms":104.763,"ecosystem":"pypi","decision":"allow","user_agent":"curl/8.7.1","remote_addr":"127.0.0.1:55982"}

Concurrent requests for one metadata document share one upstream call, and that call's `upstream` line carries the ID of the request that started it. The other requests log `joined in-flight fetch` at debug with the URL. Concurrent advisory lookups for one package also share one call, without a debug line. A blocked request can also be answered entirely from cached metadata, with no `upstream` line at all.

The OpenSSF refresh runs in the background, outside any request. Its `upstream` lines to `codeload.github.com` have no `request_id`.

### Send your own request ID

To tie a request to an ID from your own system, such as a load balancer's trace ID or a CI job ID, send it in `X-Request-Id`. pkgwarden keeps it when it is 1 to 64 characters, each a letter, a digit, `.`, `_`, or `-`. Otherwise pkgwarden replaces it with a generated ID: 32 lowercase hexadecimal digits. Either way, the response carries the ID that pkgwarden used.

	$ curl -s -o /dev/null -D - -H 'X-Request-Id: docs-trace-1' http://127.0.0.1:18181/npm/ms/-/ms-2.1.3.tgz | grep -i x-request-id
	X-Request-Id: docs-trace-1

These log lines were captured on 2026-11-07 for that request:

	{"time":"2026-11-07T18:36:28.521046-05:00","level":"INFO","msg":"upstream","request_id":"docs-trace-1","method":"GET","host":"registry.npmjs.org","path":"/ms","status":200,"duration_ms":143.863}
	{"time":"2026-11-07T18:36:28.536169-05:00","level":"INFO","msg":"upstream","request_id":"docs-trace-1","method":"GET","host":"api.npmjs.org","path":"/downloads/point/last-week/ms","status":200,"duration_ms":158.938}
	{"time":"2026-11-07T18:36:28.807438-05:00","level":"INFO","msg":"upstream","request_id":"docs-trace-1","method":"POST","host":"api.osv.dev","path":"/v1/query","status":200,"content_length":4293,"duration_ms":264.121}
	{"time":"2026-11-07T18:36:28.85829-05:00","level":"INFO","msg":"upstream","request_id":"docs-trace-1","method":"GET","host":"registry.npmjs.org","path":"/ms/-/ms-2.1.3.tgz","status":200,"content_length":2967,"duration_ms":37.591}
	{"time":"2026-11-07T18:36:28.858953-05:00","level":"INFO","msg":"request","request_id":"docs-trace-1","method":"GET","path":"/npm/ms/-/ms-2.1.3.tgz","status":200,"bytes":2967,"duration_ms":481.918,"ecosystem":"npm","decision":"allow","user_agent":"curl/8.7.1","remote_addr":"127.0.0.1:55972"}

Package managers do not send `X-Request-Id`. To give their requests IDs from your own system, set the header in a reverse proxy in front of pkgwarden.
