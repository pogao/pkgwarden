# How pkgwarden works

pkgwarden sits between package managers and the public registries. This page explains the path a request takes, why pkgwarden both filters metadata and refuses downloads, and what it leaves out on purpose.

## A request passes through an adapter and the engine

pkgwarden mounts one adapter per ecosystem, each under its own URL prefix. The prefixes are `/npm/`, `/pypi/`, `/rubygems/`, `/go/`, and `/cargo/`. Each adapter speaks its registry's protocol to the client and to the upstream registry. The policy engine in `internal/policy` knows nothing about protocols.

A request for package metadata goes like this:

1. The client asks the adapter for a package, such as `GET /npm/express` or `GET /pypi/simple/requests/`.
2. The adapter fetches what it needs from the upstream registry. For npm that is the full packument. For PyPI it is the JSON API document. Go needs the version list and one `.info` file per version.
3. The adapter translates that data into a `policy.Package`.
4. The engine assesses the package. It runs the allowlist, the [cooldown](cooldown.md), the [advisory lookup](advisories.md), and the [heuristics](heuristics.md), and returns one `policy.Assessment`.
5. The adapter rewrites the upstream document. It removes the blocked versions. Where the document holds absolute download links, it points them back at pkgwarden.
6. The client resolves against the filtered document as if it came from the registry.

A request for a file, such as an npm tarball or a Python wheel, runs the same assessment and applies the verdict of the version the file belongs to. If the version is allowed, pkgwarden streams the file from upstream. If it is blocked, pkgwarden answers 403 and never contacts the file host.

## One request ID ties the log lines together

Before a request reaches an adapter, pkgwarden gives it an ID, or keeps a well-formed `X-Request-Id` that the client or a load balancer sent. The ID travels in the request's context. Every upstream call made for the request logs an `upstream` line with that ID, and so do the `blocked` and `serving with warnings` lines. When the response is done, pkgwarden logs one `request` line with the ID, and returns the ID in the `X-Request-Id` header. A 403 body ends with it too. The ID never goes upstream.

The middleware that assigns the ID and the transport under the upstream HTTP client also count each inbound request and each outbound call in the Prometheus metrics at `/metrics`. The adapters count policy decisions and served files where they apply the verdict. [Metrics and request tracing](observability.md) lists the metrics and shows a full trace.

## Every adapter translates into one model

The engine only sees two types, defined in `internal/policy/policy.go`.

A `Package` has an ecosystem, a name, the time it was first published, a weekly download estimate, and a list of releases. A `Release` has a version, its publish time, the accounts that published it, and whether installing it runs install scripts.

Registries do not publish the same facts, so adapters leave fields empty when upstream has nothing. Go reports no download counts, so its `WeeklyDownloads` is `UnknownDownloads`. PyPI, RubyGems, and Go name no publisher per release, so `Publishers` is nil there. A check that needs a missing field does not fire. The [heuristics reference](heuristics.md#what-data-each-ecosystem-provides) lists what each adapter fills in.

Keeping the protocols out of the engine is what lets one policy apply the same way to five ecosystems. The cost is that a check can only use data every adapter can produce, or must tolerate its absence.

## One assessment covers every release

The engine assesses a whole package at once, never a single version. Advisory databases answer per package, so one OSV query returns every advisory for every release. Metadata filtering also needs a verdict for every version in the same response.

An `Assessment` holds two kinds of verdict:

- The package verdict carries findings that apply to every release, such as a package-wide malicious report, a failed advisory lookup, or a typosquat score.
- Each release verdict carries findings for that version only, such as a cooldown block or a vulnerability whose range covers it.

`Assessment.Release(version)` merges the package verdict into the release verdict. A version that upstream did not report gets an `unknown-release` block. That rule catches a request for a version that was unpublished or never existed, such as a lockfile entry for a release the registry removed.

A download request repeats the assessment for the whole package. The upstream metadata and the advisory results come from caches, so the repeat costs little after the first request.

## Filtering metadata and refusing downloads do different jobs

pkgwarden does both, because each one alone fails a common case.

Filtering metadata keeps resolvers working. A resolver that never sees a blocked version picks the newest allowed one on its own, with no error and no change to your manifests. If the release tagged `latest` is too new, npm installs the newest allowed release below it.

Refusing downloads covers every path that skips resolution. A lockfile names exact versions and often exact URLs. A user can paste a tarball URL. In both cases the client goes straight to a file, and only the 403 on that file stops it.

The two layers also explain what you see when a release is blocked. A client that resolved against filtered metadata reports that no matching version exists, without pkgwarden's reason. A client that requested the file directly prints the 403 body, which names the rule. `GET /api/v1/check` shows the full reason in both cases. The [package manager guide](package-managers.md) shows the real output of each client.

When the package verdict itself blocks, there is nothing useful to filter. The metadata request gets the 403. RubyGems is the one exception, as [A fully blocked gem gets an empty info file](#a-fully-blocked-gem-gets-an-empty-info-file) explains.

## A block is always a 403

Every adapter answers a block with HTTP 403 and a short reason in the body. A 404 or a 410 would be wrong for two reasons.

The go command reads a 404 or 410 as a missing module and moves to the next `GOPROXY` entry. With `GOPROXY=pkgwarden,direct`, a 404 would send the go command straight to the origin and skip the policy. A 403 stops it.

A 403 also tells you what happened. npm prints the body of a 403. The go command prints it as `server response:`. A 404 says the package does not exist, which sends you looking for a typo.

A warning never changes the status. pkgwarden serves the response, adds the `X-Pkgwarden-Warning` header, and logs the reasons.

## A fully blocked gem gets an empty info file

RubyGems is the exception to the 403 rule. When the package verdict blocks a gem, `/rubygems/info/<gem>` answers 200 with a body that holds only the `---` header line. Bundler then sees a gem with no versions and reports that it cannot find it.

A 403 on an info file makes Bundler give up on the compact index for the whole source. It then resolves from the full index, which pkgwarden passes through unfiltered. One blocked gem would turn off filtering for every gem in the Gemfile. An empty info file blocks the one gem and keeps the compact index in use. The download of any version of that gem still gets the 403.

## Caching keeps upstream traffic low

pkgwarden keeps four caches in memory. None survives a restart. `pkgwarden_cache_requests_total` counts the hits and misses of the first three, and the `pkgwarden_openssf_` metrics show the state of the fourth. `pkgwarden_advisory_source_enabled{source="openssf"}` is `1` only when the fourth exists.

- pkgwarden caches upstream metadata, such as packuments, index files, version lists, and download counts, for `-metadata-ttl` (default 5 minutes). The cache holds at most 512 documents. Concurrent requests for the same document share one upstream round trip.
- pkgwarden caches advisory lookups per ecosystem and package name for `-advisory-ttl` (default 1 hour). The cache holds at most 10000 packages. A failed lookup is not cached, so the next request tries again.
- The Go adapter caches the publish time from each version's `.info` file for 24 hours. The cache holds at most 100000 module versions. It is separate from the metadata cache, so a module with thousands of versions neither overflows it nor pushes out other ecosystems' documents. A `.info` file that upstream does not have is not cached, so the next request tries again.
- The OpenSSF dataset, when `-openssf` is set, lives in an in-memory index that a background task rebuilds every `-openssf-refresh` (default 6 hours). After a failed rebuild, the task retries sooner, starting at 30 seconds.

pkgwarden never caches artifacts. It does not cache the assessment either. It recomputes the assessment from the cached inputs on every request, so a release leaves its cooldown the moment it reaches the age, without waiting for a cache to expire.

The first request for a Go module with many versions is the slow case. The adapter fetches one `.info` file per listed version, eight at a time, to learn each publish time. Later requests fetch only the `.info` files missing from the cache.

## Failing closed is the default

If an advisory source cannot be reached, pkgwarden blocks the whole package with the `advisory-lookup` rule. A proxy that serves packages it could not check gives a false sense of safety, so this default is right for most teams. The price is that an OSV outage stops every install of a package that is not already in the advisory cache. `-fail-open` turns those blocks into warnings. Choose it when a build that cannot install is worse for you than a build that installs an unchecked release.

## What pkgwarden does not do

Some limits are deliberate. Knowing them helps you deploy pkgwarden in the right place.

- It does not store artifacts. Every allowed download streams from the upstream registry, so pkgwarden is not a mirror and does not help when the registry is down.
- It does not authenticate clients. Anyone who can reach the port can install through it and query `/api/v1/check`. Put it on a private network or behind a proxy that authenticates.
- It does not forward client credentials. Adapters copy only named headers upstream, such as `Accept`, `Range`, and conditional headers, so a token meant for pkgwarden never reaches a public registry.
- It does not proxy private registries. The upstream URLs are fixed to the public registries. Only the OSV URL is configurable, through `-osv-url`.
- It does not inspect package contents. Every check works from registry metadata and advisory data. The `install-scripts` signal reads the `scripts` field of an npm manifest, not the tarball.
- It does not export traces. Request IDs tie log lines together, but pkgwarden sends no spans to a tracing backend. See [the log reference](deployment.md#read-the-logs).
