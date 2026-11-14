# Cooldown

The cooldown blocks every release younger than `-cooldown`. The default is `168h`, which is 7 days. A new release becomes available the moment it reaches that age. A cooldown gives registries and advisory databases time to catch a bad release before your builds install it.

## What it blocks

The cooldown check runs on each release of a package. It produces a finding with rule `cooldown` and decision `block` in three cases.

| Case | Reason text |
| --- | --- |
| The release is younger than `-cooldown`. | `published <age> ago, inside the <cooldown> cooldown` |
| With [`-go-index`](#go-measure-from-the-first-seen-time), `proxy.golang.org` first served the Go release less than `-cooldown` ago, later than its publish time. | `first seen upstream <age> ago (<time>), inside the <cooldown> cooldown` |
| Upstream reports no publish time for the release. | `publish time unknown, so the cooldown cannot be verified` |

Ages under one day print as hours and minutes, such as `3h42m0s`. Longer ages print as days and hours, such as `7d` or `2d5h`. A publish time in the future counts as an age of zero, so the release is blocked with `published 0s ago`.

A release that is past the cooldown can still hold a file that is not. That happens on PyPI and RubyGems, which take new files for an existing version at any time. pkgwarden holds that file back and serves the rest of the release. See [Files added to an old release](#files-added-to-an-old-release).

An allowlisted package skips the cooldown along with every other check. See [`-allow`](configuration.md#-allow).

## How each ecosystem measures age

The age is the time between now and the publish time the adapter reads from upstream.

| Ecosystem | Publish time of a release |
| --- | --- |
| npm | The version's entry in the packument's `time` object. |
| PyPI | The earliest `upload_time_iso_8601` among the release's files in `https://pypi.org/pypi/<project>/json`. Each file also keeps its own `upload_time_iso_8601`. |
| RubyGems | The earliest `created_at` among the version's platform entries in `https://rubygems.org/api/v1/versions/<gem>.json`. Each platform gem also keeps its own `created_at`. |
| Go | The `Time` field of the version's `.info` file from `https://proxy.golang.org`. With `-go-index`, the later of that and the time `proxy.golang.org` first served the version. A listed version whose `.info` answers 404 or 410 has an unknown publish time. An unlisted version whose `.info` answers 404 or 410 is not published, so it gets `unknown-release` instead. |
| Cargo | The version's `created_at` in `https://crates.io/api/v1/crates/<crate>`. |

These sources set two limits.

- Go's `.info` time is the commit time, which the author sets, not the time the version was tagged or first fetched. A new tag on an old commit passes the cooldown at once. [`-go-index`](#go-measure-from-the-first-seen-time) closes most of this gap.
- A PyPI release with no files is not a release to pkgwarden. The adapter drops it before the engine sees it.

## Files added to an old release

PyPI accepts a new file for an existing release at any time, such as a wheel for a new Python version. RubyGems accepts a new platform gem, such as `x86_64-linux`, for an existing version. Installers pick the new file up without a version change, so the cooldown applies to each file's own upload time as well as to the release.

A file uploaded less than `-cooldown` ago, to a release whose earliest file is older, is held back:

- The PyPI project page leaves the file out, in both its HTML and its JSON form. The RubyGems `/info/<gem>` file leaves out the line for that platform.
- A download of the file gets a 403 with rule `cooldown`. So does its PEP 658 `.metadata` file on PyPI, and its `/gems/`, `/downloads/`, and `quick/Marshal.4.8` gemspec URLs on RubyGems.
- The rest of the release is served. Its verdict is `warn`, with one `cooldown` finding at `warn` for each held-back file. `/api/v1/check` reports it, and downloads of the release's other files carry it in `X-Pkgwarden-Warning`.

The block on the file and the warning on the release give the same reason, which starts with the file name, such as `demo_pkg-1.0.1-py3-none-any.whl: published 2d ago, inside the 7d cooldown`. A file with no upload time is held back with `<file>: publish time unknown, so the cooldown cannot be verified`.

When the release's earliest file is itself inside the cooldown, the whole release is blocked as before. Its files then carry only the release's finding. The heuristics keep using the earliest upload as the release's publish time.

A release whose files are uploaded over several hours becomes available one file at a time. Wheels built by CI often arrive this way.

## Go: measure from the first-seen time

`-go-index` makes pkgwarden measure a Go release's age from the later of two times. One is the `.info` time. The other is the time `proxy.golang.org` first served the version. pkgwarden reads the second from the Go module index at `https://index.golang.org/index`, a public feed of every module version the proxy has served. The proxy sets that time when it first fetches the version, so a module author cannot backdate it. The flag is off by default because of its startup cost.

When the first-seen time is the later one, the finding names it. This is a real example, captured on 2026-11-14. The only version of `github.com/nogochain/nogocore`, `v1.0.0`, has a `.info` time of `2026-06-20T13:08:51Z`, so it passes the cooldown without the flag. The index shows that `proxy.golang.org` first served it at 13:39 UTC on the day of the capture:

	$ curl -s 'http://127.0.0.1:60960/api/v1/check?ecosystem=go&name=github.com/nogochain/nogocore&version=v1.0.0'
	{
	  "ecosystem": "go",
	  "name": "github.com/nogochain/nogocore",
	  "version": "v1.0.0",
	  "decision": "block",
	  "findings": [
	    {
	      "rule": "cooldown",
	      "decision": "block",
	      "reason": "first seen upstream 2h49m0s ago (2026-11-14T13:39:48Z), inside the 7d cooldown"
	    }
	  ]
	}

The version list through pkgwarden was empty, `@latest` and the `.zip` got 403 with the same reason, and `go get github.com/nogochain/nogocore@v1.0.0` failed with it.

### How pkgwarden reads the index

1. At startup, a background task reads the feed from `-cooldown` ago up to now, 2000 entries per request. It keeps each module version with its first-seen time in memory. pkgwarden serves requests from the start.
2. When that first read reaches the end of the feed, pkgwarden logs `go index synced` with the number of versions it holds, the number of requests, and the time it took.
3. After that, the task reads new entries every 30 seconds. It drops entries first seen more than `-cooldown` ago, since they can no longer block anything. Each request carries a `nonce` parameter of its own. The index lets shared caches answer a repeated URL for up to 5 minutes, and a read that finds nothing new would otherwise repeat its URL and get that stale answer.
4. A version that nobody has fetched has no entry yet. pkgwarden's own `.info` request is what makes `proxy.golang.org` fetch it. The proxy stamps the entry with a time just before it answers, but the entry shows up in the feed only some seconds later. The feed grows in time order, so pkgwarden holds every version first served up to the newest entry it has read. Before pkgwarden judges a version whose `.info` file it fetched, it waits until that newest entry is at least a second later than the fetch. While a request waits, the task reads at most once a second, and the request waits at most 10 seconds. On 2026-11-14, twelve first fetches of never-fetched versions through pkgwarden waited 2.2 to 9.6 seconds after the `.info` answer, and each found the entry that pkgwarden's own request had created.

pkgwarden compares the feed's time with its own clock, so keep the host clock synchronized. The extra second covers a clock that runs up to a second behind. A clock that runs ahead makes these requests wait longer, up to the 10 seconds.

### What it costs

These numbers come from one start with the default 7-day cooldown on 2026-11-14. The feed grows with Go traffic, so a start on a weekday reads more.

| Measure | Value |
| --- | --- |
| Requests to read 7 days of the feed | 212 |
| Data downloaded | 56.5 MB |
| Time until `go index synced` | 6 minutes 52 seconds |
| Module versions kept | 423,641 |
| Go heap in use (`go_memstats_heap_inuse_bytes`) | 4.5 MB before the read, 98 MB after |
| Resident memory (`process_resident_memory_bytes`) | 24 MB before the read, 122 MB after |

After the first read, pkgwarden sends one small request every 30 seconds, plus at most one a second while requests for newly fetched versions wait. The time and the memory grow with `-cooldown`. The data lives only in memory, so every restart reads the feed again.

The wait in step 4 applies to every `.info` file pkgwarden fetches, not only to new versions. So the first request for a module, and for any version whose `.info` time pkgwarden has not cached in the last 24 hours, takes a few seconds longer than without the flag.

A whole build pays that wait for most of its modules, because `go` fetches only a few modules at a time. On 2026-11-14, with `-cooldown 24h`, each test started a fresh pkgwarden and an empty Go module cache, in three rounds that alternated which side went first. `go mod download` of the 188 modules that `github.com/prometheus/prometheus` v0.54.1 requires took 107 to 122 seconds with the flag and 36 to 39 seconds without it. A `go build` with 5 direct dependencies, 59 modules in all, took 13 to 17 seconds with the flag and 6 to 7 seconds without it. Repeating the download on the same pkgwarden, with the `.info` times already cached, took 26 to 35 seconds with the flag and 27 to 28 seconds without it.

### When the index cannot answer

The index never makes a Go install fail, and it delays a request by at most 10 seconds. In these cases pkgwarden stops waiting for the feed. It still uses the first-seen time of every release whose entry it has read, and it judges the other releases by their `.info` time alone, as without the flag:

- Until the first read reaches the end of the feed.
- While the last read of the feed failed. A read tries a failed request once more before it fails. pkgwarden then logs `go index sync failed`. If a request asked for a read while the failed read ran, the next read starts 1 second after the failure. Otherwise it starts 30 seconds after the failure. Requests that arrive after the failure do not ask for a read.
- When the newest entry read is still not a second past the `.info` fetch after 10 seconds. In a 12-minute watch of the feed on 2026-11-14, the newest entry was 2.7 seconds old at the median and more than 9 seconds old in 22 of 240 reads, with a maximum of 24 seconds. So some first fetches end up in this case.
- While pkgwarden shuts down.

Until the first read finishes, pkgwarden logs `go index behind, judging by commit time` at debug level. In the other three cases it logs that message at warning level with the module, and it counts the request in `pkgwarden_go_index_fallbacks_total`. The message and the count mean that the feed was not read past the fetch, not that every release of the module was judged by commit time. A release whose entry pkgwarden read earlier still gets its first-seen time. On 2026-11-14, one request logged the warning and then got 403 `first seen upstream 0s ago`. `pkgwarden_go_index_newest_entry_timestamp_seconds` stays `0` until the first read finishes. See [Metrics and request tracing](observability.md).

### What remains

- In the cases above, a new tag on an old commit whose entry pkgwarden has not read passes the cooldown at once, as it does without the flag. A version first fetched while the feed lags is judged by its commit time until the feed catches up. The next request for the module after that finds its entry and blocks it, but the file served before is already out.
- An old version that the proxy serves for the first time waits out the cooldown like a new release. This happens to an old commit fetched by its hash, a tag in a fork, and a module path spelled with different capitalization.
- The [heuristics](heuristics.md) still use the `.info` time.
- With `-cooldown 0`, `-go-index` reads nothing.

## How to change or disable it

`-cooldown` takes a Go duration. Use the units `h`, `m`, and `s`. There is no unit for days, so write 14 days as `336h`. The environment variable is `PKGWARDEN_COOLDOWN`.

| Setting | Effect |
| --- | --- |
| `-cooldown 168h` | The default. Releases younger than 7 days are blocked. |
| `-cooldown 72h` | Releases younger than 3 days are blocked. |
| `-cooldown 0` | The cooldown is off. A release with an unknown publish time is also served. |
| `-cooldown -1h` | Rejected at startup with `pkgwarden: -cooldown must not be negative` and exit status 2. |
| `-cooldown 7d` | Rejected at startup with `pkgwarden: invalid value "7d" for flag -cooldown: parse error` and exit status 2. |

The cooldown has no per-package or per-ecosystem setting. To exempt one package from it, allowlist the package, which also exempts it from advisories and heuristics.

## What a client sees

A release inside the cooldown disappears from the metadata pkgwarden serves. A resolver then picks the newest allowed release that satisfies the constraint. npm's `latest` tag moves to the newest allowed stable release that is not newer than the version it pointed at. Other npm dist-tags that point at a blocked version are removed.

This is a real example, captured on 2026-11-07. The upstream registry had tagged `renovate@44.222.2` as `latest` about four hours earlier:

	$ curl -s 'http://127.0.0.1:18181/api/v1/check?ecosystem=npm&name=renovate&version=44.222.2'
	{
	  "ecosystem": "npm",
	  "name": "renovate",
	  "version": "44.222.2",
	  "decision": "block",
	  "findings": [
	    {
	      "rule": "cooldown",
	      "decision": "block",
	      "reason": "published 3h42m0s ago, inside the 7d cooldown"
	    }
	  ]
	}

The upstream packument tagged `latest` as `44.222.2`. The packument served by pkgwarden tagged it as `44.198.3`, and `npm view renovate version` through pkgwarden printed `44.198.3`.

A client that asks for the young version by exact number reports that no such version exists. A direct download of its file gets HTTP 403. This body was captured a few minutes after the check above:

	$ curl -s http://127.0.0.1:18181/npm/renovate/-/renovate-44.222.2.tgz
	{"error":"pkgwarden blocked npm/renovate@44.222.2: cooldown: published 3h50m0s ago, inside the 7d cooldown"}

The [package manager guide](package-managers.md) shows what each client prints.
