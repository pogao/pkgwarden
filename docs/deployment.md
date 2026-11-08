# Deploy pkgwarden

This guide builds and runs pkgwarden, puts it behind TLS, opens the network paths it needs, and explains its logs, its metrics, and its limits. For every flag, see the [configuration reference](configuration.md).

## Build and run the container image

Build the image from the repository root, then run it:

	docker build -t pkgwarden .
	docker run -p 8080:8080 pkgwarden

To label the image with a version, pass the `VERSION` build argument. pkgwarden reports it in the `version` label of `pkgwarden_build_info`. Without it, the label is `(devel)`, because the build context leaves out `.git`:

	docker build --build-arg VERSION="$(git describe --tags --always --dirty)" -t pkgwarden .

The `Dockerfile` builds a static binary with `golang:1.27-alpine` and `CGO_ENABLED=0`, then copies it into an empty `scratch` image together with the CA certificate bundle from the build image. The final image holds only those two files. It has no shell, no package manager, no `/tmp`, and no time zone data, none of which pkgwarden uses. The container runs as user and group 65532, listens on port 8080, and has `/pkgwarden` as its entrypoint. The user is numeric, so Kubernetes `runAsNonRoot: true` accepts the image. The CA bundle is as recent as the `golang:1.27-alpine` image the build used, so rebuild to pick up certificate changes.

To pass flags, put them after the image name:

	docker run -p 8080:8080 pkgwarden -cooldown 72h -log-level debug

To pass settings as environment variables instead, use `-e`:

	docker run -p 8080:8080 -e PKGWARDEN_COOLDOWN=72h -e GITHUB_TOKEN pkgwarden

## Build for several architectures

The `Dockerfile` cross-compiles. It runs the Go toolchain on the build machine's platform and sets `GOOS` and `GOARCH` from the target platform, so no emulation is needed.

To build one other architecture into your local image store, run this:

	docker buildx build --platform linux/amd64 --load -t pkgwarden:amd64 .

To build a multi-architecture image, create a builder that uses the `docker-container` driver, then build and push:

	docker buildx create --name multiarch --driver docker-container --use
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t registry.example.com/pkgwarden:latest --push .

The default `docker` driver refuses a multi-platform build with `ERROR: failed to build: Multi-platform build is not supported for the docker driver.` unless the containerd image store is turned on.

## Run from source

You need Go 1.27.3 or later, as `go.mod` states. To run pkgwarden directly, run this from the repository root:

	go run ./cmd/pkgwarden -listen :8080

To build a binary, run this. The `bin/` directory is ignored by git.

	go build -o bin/pkgwarden ./cmd/pkgwarden
	./bin/pkgwarden -listen :8080

## Serve it over TLS

pkgwarden serves plain HTTP only. To serve HTTPS, put a reverse proxy or a load balancer in front of it and terminate TLS there.

1. Forward every path to pkgwarden unchanged, and keep the `Host` header.
2. Set `-public-url` to the address clients use, such as `-public-url https://pkgwarden.example.com`. pkgwarden writes it into npm tarball links, PyPI file links, and Cargo's `dl` URL.
3. If you cannot set `-public-url`, send `X-Forwarded-Proto: https` from the proxy. pkgwarden then builds links from that scheme and the `Host` header. It ignores `X-Forwarded-Host`.

If you serve pkgwarden under a path, such as `https://example.com/pkgwarden/`, include the path in `-public-url` and have the proxy strip it before it forwards the request. pkgwarden expects its routes at the server root.

pkgwarden sets no write timeout, so a large download can take as long as it needs. Make sure the proxy in front allows the same.

## Allow outbound traffic

pkgwarden fetches everything at request time. It needs HTTPS access to these hosts:

| Host | Used for | When |
| --- | --- | --- |
| `registry.npmjs.org` | npm metadata, tarballs, `npm audit`, and other npm requests | Always |
| `api.npmjs.org` | npm weekly download counts | Always |
| `pypi.org` | The PyPI JSON API and the root simple index | Always |
| `files.pythonhosted.org` | PyPI distribution files | Always |
| `pypistats.org` | PyPI weekly download counts | Always |
| `rubygems.org` | RubyGems metadata, compact index files, and gems | Always |
| `proxy.golang.org` | Go module lists, `.info`, `.mod`, and `.zip` files | Always |
| `index.crates.io` | Cargo sparse index files | Always |
| `crates.io` | Crate metadata, publishers, and download counts | Always |
| `static.crates.io` | Crate files | Always |
| `api.osv.dev` | OSV advisory queries | Unless `-osv-url` points elsewhere |
| `api.github.com` | GitHub Advisory Database queries | When `-ghsa-token` is set |
| `codeload.github.com` | The OpenSSF malicious-packages archive | When `-openssf` is set |

pkgwarden reads `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` for its outbound requests.

Clients need to reach pkgwarden only, with one exception. Go clients also contact `sum.golang.org`, because pkgwarden does not serve the checksum database. See [Go](package-managers.md#go).

These timeouts apply to outbound requests:

| Step | Timeout |
| --- | --- |
| Opening a TCP connection | 10 seconds |
| The TLS handshake | 10 seconds |
| Waiting for response headers | 60 seconds |
| A shared metadata fetch, body included | 2 minutes |
| A shared advisory lookup, all sources together | 30 seconds |
| A pypistats download count | 5 seconds |

pkgwarden reads at most 128 MiB of a metadata document and drops the rest. A JSON document cut this way fails to parse.

## Read the logs

pkgwarden writes one JSON object per line to stderr. Each line has `time`, `level`, and `msg`. A line logged while pkgwarden handles a request also has `request_id`, right after `msg`. It is the same ID that the response carries in `X-Request-Id`. To follow one request through these lines, see [Follow one request through the logs](observability.md#follow-one-request-through-the-logs).

pkgwarden logs these messages:

| `msg` | Level | Meaning | Other fields |
| --- | --- | --- | --- |
| `listening` | INFO | pkgwarden bound its ports and started serving. `addr` is the bound address, so `-listen :0` shows the port the system picked. `metrics_addr` is where `/metrics` is served, which is `addr` unless `-metrics-listen` is set. | `addr`, `metrics_addr`, `cooldown`, `ghsa`, `openssf`, `heuristics` |
| `request` | INFO, DEBUG for `/healthz` and `/metrics` | pkgwarden finished a response. `path` has no query string. `bytes` counts the body pkgwarden sent. `decision` is the `X-Pkgwarden-Decision` header, left out when the response did not go through the policy. | `method`, `path`, `status`, `bytes`, `duration_ms`, `ecosystem`, `decision`, `user_agent`, `remote_addr` |
| `upstream` | INFO | pkgwarden got a response, or an error, from a registry or advisory source. `path` has no query string. `content_length` is left out when upstream did not send one. `duration_ms` runs until the response headers arrived. No header value is logged. | `method`, `host`, `path`, `status`, `content_length`, `duration_ms`, or `err` instead of `status` |
| `blocked` | INFO | pkgwarden answered a request with 403. | `ecosystem`, `package`, `version`, `stage`, `rules`, `reasons` |
| `serving with warnings` | WARN | pkgwarden served a response whose verdict was `warn`. | `ecosystem`, `package`, `version`, `stage`, `rules`, `reasons` |
| `hiding every version` | INFO | pkgwarden served an empty RubyGems info file for a gem blocked at package level. | `ecosystem`, `package`, `stage`, `rules`, `findings` |
| `artifact relay interrupted` | WARN | Copying a package file to the client failed partway, such as when the client disconnected. | `ecosystem`, `package`, `version`, `bytes`, `err` |
| `advisory dataset refresh failed` | ERROR | An OpenSSF download or parse failed. The previous index stays in use, and pkgwarden retries with backoff. | `source`, `err` |
| `metadata cache hit` | DEBUG | pkgwarden answered a metadata fetch from its cache, with no upstream call. | `url` |
| `joined in-flight fetch` | DEBUG | A metadata fetch shared the upstream call that another request started. That call's `upstream` line carries the other request's ID. | `url` |
| `advisory cache hit` | DEBUG | pkgwarden answered an advisory lookup from its cache, with no upstream call. | `ecosystem`, `package` |
| `pypi download count unavailable` | DEBUG | pypistats did not answer in time, or answered without a count. | `project`, `err` |
| `exiting` | ERROR | pkgwarden stopped because of an error. | `err` |

`version` is left out of `blocked` and `serving with warnings` when the verdict covers the whole package. `stage` is `metadata` or `artifact`, as in [Label values](observability.md#label-values). `rules` lists each rule behind the decision once. `reasons` holds the findings at the verdict's decision, as `<rule>: <reason>` joined with `; `. Unlike the 403 body, it is not shortened. `findings` holds the full finding objects.

These lines were captured on 2026-11-07. The long ones are trimmed with `...`:

	{"time":"2026-11-07T18:36:28.12966-05:00","level":"INFO","msg":"listening","addr":"127.0.0.1:18181","metrics_addr":"127.0.0.1:18181","cooldown":"168h0m0s","ghsa":false,"openssf":false,"heuristics":true}
	{"time":"2026-11-07T18:36:32.255631-05:00","level":"INFO","msg":"upstream","request_id":"f3b81df0468fbbea48d308745598b8ed","method":"GET","host":"crates.io","path":"/api/v1/crates/smallvec","status":200,"duration_ms":233.876}
	{"time":"2026-11-07T18:36:32.456401-05:00","level":"INFO","msg":"blocked","request_id":"f3b81df0468fbbea48d308745598b8ed","ecosystem":"cargo","package":"smallvec","version":"1.6.0","stage":"artifact","rules":["advisory/vulnerability"],"reasons":"advisory/vulnerability: GHSA-43w2-9j62-hq99 (critical vulnerability, via osv): Buffer overflow in SmallVec::insert_many https://osv.dev/vulnerability/GHSA-43w2-9j62-hq99"}
	{"time":"2026-11-07T18:36:32.456606-05:00","level":"INFO","msg":"request","request_id":"f3b81df0468fbbea48d308745598b8ed","method":"GET","path":"/cargo/api/v1/crates/smallvec/1.6.0/download","status":403,"bytes":244,"duration_ms":435.098,"ecosystem":"cargo","decision":"block","user_agent":"curl/8.7.1","remote_addr":"127.0.0.1:55999"}
	{"time":"2026-11-07T18:36:34.113278-05:00","level":"WARN","msg":"serving with warnings","request_id":"7a03613358de0b64d235462c9cbbf1f3","ecosystem":"pypi","package":"requests","version":"2.31.0","stage":"artifact","rules":["advisory/vulnerability"],"reasons":"advisory/vulnerability: GHSA-9hjg-9r4m-mvj7 (medium vulnerability, via osv): Requests vulnerable to .netrc credentials leak via malicious URLs https:/..."}
	{"time":"2026-11-07T18:36:34.761419-05:00","level":"INFO","msg":"hiding every version","request_id":"69a6fc7537a6c2da28e3936575013ffd","ecosystem":"rubygems","package":"nokogirl","stage":"metadata","rules":["heuristic/typosquat","heuristic/low-downloads","heuristic/score"],"findings":[{"rule":"heuristic/typosquat","decision":"block","reason":"resembles popular package \"nokogiri\" (one edit away)"},...]}

pkgwarden does not log successful OpenSSF refreshes or a clean shutdown. Every response with a `warn` verdict logs its own line. A package-level warning therefore appears once for the metadata document and once for each download.

## Scrape it with Prometheus

pkgwarden serves Prometheus metrics at `/metrics`. [Metrics and request tracing](observability.md) lists every metric with example queries.

`/metrics` is as open as every other route, because pkgwarden has no authentication. To serve it on a port that package managers cannot reach, start pkgwarden with `-metrics-listen` and publish that port only to your monitoring network:

	docker run -p 8080:8080 -p 127.0.0.1:9090:9090 pkgwarden -metrics-listen :9090

Then add a scrape job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: pkgwarden
    static_configs:
      - targets: ["pkgwarden.internal:9090"]
```

Without `-metrics-listen`, scrape the main port, such as `pkgwarden.internal:8080`. Scrapes of `/metrics` log their `request` line at debug, so they do not fill the log at the default level.

## Check its health

`GET /healthz` returns 200 and `ok`. It does not contact any upstream, so it shows only that the process is serving. To see whether upstreams and advisory sources answer, watch `pkgwarden_upstream_requests_total` instead. See [Example queries](observability.md#example-queries). The image has no shell or `curl`, so use your orchestrator's HTTP probe rather than a command inside the container.

## Stop it

pkgwarden stops on `SIGINT` or `SIGTERM`. It stops accepting connections, waits up to 15 seconds for requests in progress, and exits with status 0. If a request is still running after 15 seconds, pkgwarden logs `exiting` with the error and exits with status 1.

`docker stop` sends `SIGTERM` and kills the container 10 seconds later by default. To give downloads the full 15 seconds, use `docker stop -t 20`.

## Secure it

- pkgwarden has no authentication. Anyone who can reach the port can install packages through it, read verdicts from `/api/v1/check`, read `/metrics`, and make it send requests to the public registries. Expose it only on a private network, or put an authenticating proxy in front of it. `-metrics-listen` moves `/metrics` to its own port.
- The logs name every package that clients request, with the client's address and user agent. Treat them as you treat an access log.
- pkgwarden never forwards client credentials upstream. Each adapter copies only named headers, such as `Accept`, `Range`, and conditional headers. An `Authorization` header sent to pkgwarden stays there.
- The GitHub token goes only to `api.github.com`. pkgwarden refuses a pagination link to any other host.
- `pkgwarden -h` never prints a token. The help text names `$GITHUB_TOKEN` as the default of `-ghsa-token`.
- PyPI file links never carry an upstream URL. pkgwarden looks each file up in PyPI's metadata and serves it only from `files.pythonhosted.org`.

## Know its limits

- pkgwarden stores no artifacts. Every allowed download streams from the upstream registry. When a registry is down, installs from it fail.
- Every cache is in memory and empty after a restart, so the first requests after a restart are slower.
- The upstream registries are fixed to the public ones. pkgwarden cannot front a private registry.
- The RubyGems legacy indexes pass through unfiltered. See [Bundler and gem](package-managers.md#bundler-and-gem).
- The popular-package lists for typosquat detection are built into the binary. Refreshing them needs a new build. See [Refresh the popular-package lists](development.md#refresh-the-popular-package-lists).
