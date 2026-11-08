# Cooldown

The cooldown blocks every release younger than `-cooldown`. The default is `168h`, which is 7 days. A new release becomes available the moment it reaches that age. A cooldown gives registries and advisory databases time to catch a bad release before your builds install it.

## What it blocks

The cooldown check runs on each release of a package. It produces a finding with rule `cooldown` and decision `block` in two cases.

| Case | Reason text |
| --- | --- |
| The release is younger than `-cooldown`. | `published <age> ago, inside the <cooldown> cooldown` |
| Upstream reports no publish time for the release. | `publish time unknown, so the cooldown cannot be verified` |

Ages under one day print as hours and minutes, such as `3h42m0s`. Longer ages print as days and hours, such as `7d` or `2d5h`. A publish time in the future counts as an age of zero, so the release is blocked with `published 0s ago`.

The cooldown never warns. A release is either old enough or blocked.

An allowlisted package skips the cooldown along with every other check. See [`-allow`](configuration.md#-allow).

## How each ecosystem measures age

The age is the time between now and the publish time the adapter reads from upstream.

| Ecosystem | Publish time of a release |
| --- | --- |
| npm | The version's entry in the packument's `time` object. |
| PyPI | The earliest `upload_time_iso_8601` among the release's files in `https://pypi.org/pypi/<project>/json`. |
| RubyGems | The earliest `created_at` among the version's platform entries in `https://rubygems.org/api/v1/versions/<gem>.json`. |
| Go | The `Time` field of the version's `.info` file from `https://proxy.golang.org`. A listed version whose `.info` answers 404 or 410 has an unknown publish time. An unlisted version whose `.info` answers 404 or 410 is not published, so it gets `unknown-release` instead. |
| Cargo | The version's `created_at` in `https://crates.io/api/v1/crates/<crate>`. |

These sources set three limits.

- Go's `.info` time is the commit time, not the time the version was tagged or first fetched. A new tag on an old commit passes the cooldown at once.
- A PyPI file uploaded later to an old release is judged by the release's first upload. The same holds for a RubyGems platform gem pushed later for an existing version.
- A PyPI release with no files is not a release to pkgwarden. The adapter drops it before the engine sees it.

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
