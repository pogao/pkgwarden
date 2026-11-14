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
3. After that, the task reads new entries every 30 seconds. It drops entries first seen more than `-cooldown` ago, since they can no longer block anything.
4. A version that nobody has fetched has no entry yet. pkgwarden's own `.info` request is what makes `proxy.golang.org` fetch it, and the proxy adds the entry before it answers. So before pkgwarden judges a version whose `.info` file it fetched after the last read of the feed began, it asks for one more read and waits up to 10 seconds for it. The task reads at most once a second, so this adds at most about a second to the first request for a module. In one test the extra read took 65 milliseconds, and it found the entry that pkgwarden's own request had created.

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

### When the index cannot answer

The index never makes a Go install fail, and it delays a request by at most 10 seconds. In these cases pkgwarden judges the release by its `.info` time alone, as without the flag:

- Until the first read reaches the end of the feed.
- While the last read of the feed failed. A read tries a failed request once more before it fails. pkgwarden then logs `go index sync failed` and reads again 30 seconds later.
- When the extra read for a newly fetched version takes longer than 10 seconds.

`pkgwarden_go_index_last_success_timestamp_seconds` stays `0` until the first read finishes. See [Metrics and request tracing](observability.md).

### What remains

- In the three cases above, a new tag on an old commit passes the cooldown at once, as it does without the flag.
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
