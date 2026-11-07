# Deploy pkgwarden

This guide builds and runs pkgwarden, puts it behind TLS, opens the network paths it needs, and explains its logs and its limits. For every flag, see the [configuration reference](configuration.md).

## Build and run the container image

Build the image from the repository root, then run it:

	docker build -t pkgwarden .
	docker run -p 8080:8080 pkgwarden

The `Dockerfile` builds a static binary with `golang:1.27-alpine` and `CGO_ENABLED=0`, then copies it into `gcr.io/distroless/static-debian12:nonroot`. The container runs as the `nonroot` user, listens on port 8080, and has `/pkgwarden` as its entrypoint. The image has no shell.

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
| A shared advisory lookup, all sources together | 30 seconds |
| A pypistats download count | 5 seconds |

pkgwarden reads at most 128 MiB of a metadata document and drops the rest. A JSON document cut this way fails to parse.

## Read the logs

pkgwarden writes one JSON object per line to stderr. Each line has `time`, `level`, and `msg`. It logs these messages:

| `msg` | Level | Meaning | Other fields |
| --- | --- | --- | --- |
| `listening` | INFO | pkgwarden started. It is logged before the listener opens, so a bind error follows it. | `addr`, `cooldown`, `ghsa`, `openssf`, `heuristics` |
| `blocked` | INFO | pkgwarden answered a request with 403. | `subject`, `reasons` |
| `serving with warnings` | WARN | pkgwarden served a response whose verdict was `warn`. | `subject`, `reasons` |
| `hiding every version` | INFO | pkgwarden served an empty RubyGems info file for a gem blocked at package level. | `subject`, `findings` |
| `advisory dataset refresh failed` | ERROR | An OpenSSF download or parse failed. The previous index stays in use. | `source`, `err` |
| `pypi download count unavailable` | DEBUG | pypistats did not answer in time, or answered without a count. | `project`, `err` |
| `exiting` | ERROR | pkgwarden stopped because of an error. | `err` |

`reasons` holds the findings at the verdict's decision, as `<rule>: <reason>` joined with `; `. Unlike the 403 body, it is not shortened. `findings` holds the full finding objects.

These lines were captured on 2026-11-07. The long ones are trimmed with `...`:

	{"time":"2026-11-07T17:26:23.300353-05:00","level":"INFO","msg":"listening","addr":"127.0.0.1:18181","cooldown":"168h0m0s","ghsa":false,"openssf":false,"heuristics":true}
	{"time":"2026-11-07T17:28:40.21862-05:00","level":"INFO","msg":"blocked","subject":"cargo/smallvec@1.6.0","reasons":"advisory: GHSA-43w2-9j62-hq99 (critical vulnerability, via osv): Buffer overflow in SmallVec::insert_many https://osv.dev/vulnerability/GHSA-43w2-9j62-hq99"}
	{"time":"2026-11-07T17:26:42.420105-05:00","level":"WARN","msg":"serving with warnings","subject":"pypi/requests@2.31.0","reasons":"advisory: GHSA-9hjg-9r4m-mvj7 (medium vulnerability, via osv): Requests vulnerable to .netrc credentials leak via malicious URLs https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7; ..."}
	{"time":"2026-11-07T17:30:03.121557-05:00","level":"INFO","msg":"hiding every version","subject":"rubygems/nokogirl","findings":[{"rule":"heuristic/typosquat","decision":"block","reason":"resembles popular package \"nokogiri\" (one edit away)"},...]}

pkgwarden does not log allowed requests, successful OpenSSF refreshes, or a clean shutdown. Every response with a `warn` verdict logs its own line. A package-level warning therefore appears once for the metadata document and once for each download.

## Check its health

`GET /healthz` returns 200 and `ok`. It does not contact any upstream, so it shows only that the process is serving. The image has no shell or `curl`, so use your orchestrator's HTTP probe rather than a command inside the container.

## Stop it

pkgwarden stops on `SIGINT` or `SIGTERM`. It stops accepting connections, waits up to 15 seconds for requests in progress, and exits with status 0. If a request is still running after 15 seconds, pkgwarden logs `exiting` with the error and exits with status 1.

`docker stop` sends `SIGTERM` and kills the container 10 seconds later by default. To give downloads the full 15 seconds, use `docker stop -t 20`.

## Secure it

- pkgwarden has no authentication. Anyone who can reach the port can install packages through it, read verdicts from `/api/v1/check`, and make it send requests to the public registries. Expose it only on a private network, or put an authenticating proxy in front of it.
- pkgwarden never forwards client credentials upstream. Each adapter copies only named headers, such as `Accept`, `Range`, and conditional headers. An `Authorization` header sent to pkgwarden stays there.
- The GitHub token goes only to `api.github.com`. pkgwarden refuses a pagination link to any other host.
- `pkgwarden -h` prints the value of `GITHUB_TOKEN` or `PKGWARDEN_GHSA_TOKEN` as the default of `-ghsa-token`. Do not run it where its output is logged.
- PyPI file links never carry an upstream URL. pkgwarden looks each file up in PyPI's metadata and serves it only from `files.pythonhosted.org`.

## Know its limits

- pkgwarden stores no artifacts. Every allowed download streams from the upstream registry. When a registry is down, installs from it fail.
- Every cache is in memory and empty after a restart, so the first requests after a restart are slower.
- The upstream registries are fixed to the public ones. pkgwarden cannot front a private registry.
- The RubyGems legacy indexes pass through unfiltered. See [Bundler and gem](package-managers.md#bundler-and-gem).
- The popular-package lists for typosquat detection are built into the binary. Refreshing them needs a new build. See [Refresh the popular-package lists](development.md#refresh-the-popular-package-lists).
