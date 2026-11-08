# Advisories

pkgwarden looks up every package in public advisory databases. A release that an advisory lists as malicious is always blocked. A release inside a vulnerability's affected range is blocked or served with a warning, depending on the vulnerability's rating and `-block-severity`. The code lives in `internal/advisory`, and the rules that turn advisories into findings live in `internal/policy/engine.go`.

## Sources

pkgwarden queries up to three sources.

| Source | Queried when | Request |
| --- | --- | --- |
| OSV | Always. | `POST <osv-url>/v1/query` with the package name and the OSV ecosystem name. `-osv-url` defaults to `https://api.osv.dev`. |
| GitHub Advisory Database | `-ghsa-token` is set. It defaults to the value of `GITHUB_TOKEN`. | `GET https://api.github.com/advisories?ecosystem=<eco>&affects=<name>&per_page=100` with the token as a bearer token. |
| OpenSSF malicious-packages dataset | `-openssf` is set. | `GET https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main` in the background, then local lookups. |

OSV already imports the GitHub Advisory Database and the OpenSSF malicious-packages dataset, so OSV alone covers all three. The direct sources can report a record before OSV imports it. They do not replace OSV. If OSV fails, the lookup still fails, as [When a lookup fails](#when-a-lookup-fails) describes.

Each source names ecosystems its own way.

| pkgwarden | OSV and OpenSSF | GitHub |
| --- | --- | --- |
| `npm` | `npm` | `npm` |
| `pypi` | `PyPI` | `pip` |
| `rubygems` | `RubyGems` | `rubygems` |
| `go` | `Go` | `go` |
| `cargo` | `crates.io` | `rust` |

OSV results are paginated. pkgwarden follows up to 100 pages of at most 32 MiB each and fails the lookup beyond that. GitHub results follow the `Link` header for up to 50 pages. pkgwarden refuses a pagination link that points at another host, so the token never leaves `api.github.com`.

Withdrawn advisories are skipped in every source. OSV marks them with `withdrawn`, GitHub with `withdrawn_at`, and the OpenSSF dataset keeps them under `osv/withdrawn/`, which pkgwarden does not read.

## Malicious and vulnerable releases

Every advisory is one of two kinds.

| Kind | How pkgwarden recognizes it | Decision |
| --- | --- | --- |
| Malicious | The OSV ID or one of its aliases starts with `MAL-`. The GitHub advisory has `type` `malware`. Every entry in the OpenSSF dataset. | Always `block`, whatever `-block-severity` says. |
| Vulnerability | Every other advisory. | `block` when its rating is at or above `-block-severity`. `warn` otherwise. |

## The severity threshold

`-block-severity` sets the lowest vulnerability rating that blocks. The default is `high`.

| `-block-severity` | Blocks | Warns |
| --- | --- | --- |
| `low` | low, medium, high, critical | unrated |
| `medium` | medium, high, critical | low, unrated |
| `high` | high, critical | low, medium, unrated |
| `critical` | critical | low, medium, high, unrated |
| `none` | nothing | every vulnerability |

An unrated vulnerability never blocks, at any threshold. Malicious releases block at every threshold, including `none`. The value is case-insensitive. Any other value stops pkgwarden at startup with `pkgwarden: -block-severity "moderate": want low, medium, high, critical or none` and exit status 2.

## Where a rating comes from

pkgwarden prefers the database's own rating and computes one only when the record has none.

For an OSV record, pkgwarden reads `database_specific.severity` first. It accepts `LOW`, `MEDIUM`, `MODERATE`, `HIGH`, and `CRITICAL` in any case, and treats `MODERATE` as medium. If that field is missing or holds another value, pkgwarden computes the CVSS base score of every CVSS v3.0 and v3.1 vector in the record's `severity` list and keeps the highest rating. It maps scores the way CVSS v3.1 does.

| Base score | Rating |
| --- | --- |
| 0.1 to 3.9 | low |
| 4.0 to 6.9 | medium |
| 7.0 to 8.9 | high |
| 9.0 to 10.0 | critical |

A score of 0, a CVSS v2 or v4 vector, and a malformed vector all leave the record unrated. Temporal and environmental metrics are ignored.

For a GitHub advisory, pkgwarden reads the `severity` field. `moderate` is medium.

## Which releases an advisory affects

An advisory lists affected versions, affected ranges, or both. pkgwarden compares each published release against them with the ecosystem's own version order.

| Ecosystem | Version order |
| --- | --- |
| npm, Cargo, Go | SemVer 2.0. A leading `v` is optional, and npm's leading `=` is accepted. |
| PyPI | PEP 440. |
| RubyGems | `Gem::Version`. |

A version the ecosystem's rules cannot parse sorts after every parseable version. A range whose lower bound cannot be parsed starts at the first release.

From OSV records, pkgwarden reads the `versions` list and the ranges of type `SEMVER` and `ECOSYSTEM`. Each range starts at `introduced` and ends before `fixed`, or at `last_affected` inclusive, or never. Ranges of other types, such as `GIT`, are ignored.

From GitHub advisories, pkgwarden parses `vulnerable_version_range`. It reads `= v` as one version and `>= v`, `> v`, `< v`, and `<= v` as range bounds. It treats `> v` as `>= v`, so it blocks version `v` itself as well. A range it cannot parse adds nothing.

An advisory that ends up with no versions and no ranges for the package applies to every release. pkgwarden records it on the package verdict, so a malicious package-wide report blocks the whole package. This happens for a record that names the package without versions or ranges, for an OSV record whose only ranges are of an ignored type, and for a GitHub advisory whose ranges did not parse. A range that starts at `0` and never ends also covers every release, but pkgwarden records it on each release rather than on the package.

pkgwarden matches advisories only against releases that upstream reports. A version that upstream does not report gets an `unknown-release` block instead, with the reason `version <version> is not published upstream`. This catches a lockfile entry for a release the registry removed. The e2e script checks it with `event-stream@3.3.6`, the malicious release npm unpublished in 2018.

## How results are merged

pkgwarden queries every configured source at the same time and groups advisories that share an identifier. Two advisories belong to the same group if one's ID or alias equals the other's ID or alias, directly or through other members. A GHSA entry, its PYSEC twin, and their CVE collapse into one advisory.

The merged advisory takes these values from its group:

- The ID, summary, and URL come from the first malicious member, or the first member when none is malicious.
- The rating is the highest rating any member gives.
- The sources are joined with `+`, such as `osv+ghsa`.
- The affected versions and ranges are the union of the members'. If any member applies to every release, the merged advisory does too.

## How a finding reads

Each advisory that covers a release becomes a finding. Its rule is `advisory/malicious` when the advisory reports a malicious package, and `advisory/vulnerability` otherwise, so metrics and logs can tell the two apart. The reason has this form:

	<ID> (<rating> <kind>, via <sources>): <summary> <URL>

The rating is left out when it is unknown. An unrated vulnerability reads `unrated vulnerability`. The summary is the record's `summary`, or the first line of its details cut to 200 characters. OSV and OpenSSF findings link to `https://osv.dev/vulnerability/<ID>`. GitHub findings link to the advisory's `html_url`.

This finding was captured on 2026-11-07:

	"reason": "GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"

## Caching and timeouts

pkgwarden caches the merged result of each lookup for `-advisory-ttl`, keyed by ecosystem and normalized package name. The default is `1h`. The cache holds at most 10000 packages. When it is full, it drops expired entries first and then arbitrary ones.

Concurrent lookups for the same package share one call to the sources. That call keeps running when the request that started it is cancelled, so the requests still waiting get the result. It has a 30-second timeout.

A failed lookup is never cached. The next request for the package tries again.

`pkgwarden_cache_requests_total{cache="advisory"}` counts the hits and misses. See [Metrics and request tracing](observability.md).

## When a lookup fails

If any source fails, pkgwarden adds an `advisory-lookup` finding to the package verdict. The reason starts with `advisory lookup failed:` and names the error.

| `-fail-open` | Decision of the `advisory-lookup` finding |
| --- | --- |
| `false` (default) | `block`. The whole package is refused. |
| `true` | `warn`. The package is served with a warning. |

Results from the sources that answered still apply. If OSV fails and GitHub answers, a release that GitHub lists as vulnerable is still blocked.

This verdict was captured from an instance started with `-osv-url http://127.0.0.1:1`, a port with nothing listening:

	{
	  "ecosystem": "npm",
	  "name": "express",
	  "decision": "block",
	  "findings": [
	    {
	      "rule": "advisory-lookup",
	      "decision": "block",
	      "reason": "advisory lookup failed: osv lookup npm/express: Post \"http://127.0.0.1:1/v1/query\": dial tcp 127.0.0.1:1: connect: connection refused"
	    }
	  ]
	}

## The OpenSSF dataset

`-openssf` makes pkgwarden download the whole OpenSSF malicious-packages repository and build an in-memory index of its reports. The download is about 300 MB per refresh, so the source is off by default.

The dataset goes through these states:

1. At startup, pkgwarden starts the first download in the background. It begins serving requests at once.
2. Until the first download and parse succeed, every OpenSSF lookup fails with `openssf lookup: dataset not loaded yet`. Every package therefore gets an `advisory-lookup` block, or a warning with `-fail-open`.
3. After the first load, lookups read the index and never touch the network.
4. Every `-openssf-refresh` (default `6h`), pkgwarden downloads the archive again. It replaces the index only after the new archive parses completely. If a refresh fails, the previous index stays in use and pkgwarden logs `advisory dataset refresh failed`.
5. After a failed download or parse, pkgwarden retries after 30 seconds. Each further failure doubles the wait, up to `-openssf-refresh`. The first success returns it to the `-openssf-refresh` schedule.

A `-openssf-refresh` of `0` or less loads the dataset once and never refreshes it.

If the first load fails, lookups keep failing, and every package stays blocked, until a retry succeeds. With the default settings, the waits between attempts are 30 seconds, 1 minute, 2 minutes, and so on, and never more than 6 hours. Watch for `advisory dataset refresh failed` after you turn this source on.

On one test run on 2026-11-07, the first load finished about 11 seconds after startup, and the process then used about 230 MB of resident memory. That is a single measurement on one machine and network.

pkgwarden caps the archive at 2 GiB compressed and 16 GiB unpacked, and each report at 4 MiB. A larger archive fails the refresh.
