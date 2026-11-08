# Heuristics

Heuristics catch packages that no advisory lists yet. Each signal that fires adds its weight to a score. A score at or above `-heuristics-warn` serves the release with a warning, and a score at or above `-heuristics-block` blocks it. The code lives in `internal/policy/heuristics.go` and `internal/policy/typosquat.go`.

`-heuristics=false` turns every signal off. Allowlisted packages skip heuristics along with every other check.

## Signals and weights

pkgwarden has five signals. Their weights are constants in `internal/policy/heuristics.go`, and no flag changes them.

| Rule | Weight | Applies to | Fires when |
| --- | --- | --- | --- |
| `heuristic/typosquat` | 60 | Package | The name resembles a name on the ecosystem's popular list without being on it. See [Typosquat detection](#typosquat-detection). |
| `heuristic/new-package` | 30 | Package | The package was first published less than `-new-package-age` ago. The default is `720h`, which is 30 days. |
| `heuristic/low-downloads` | 20 | Package | The registry reports a weekly download count, and it is below `-low-downloads`. The default is 100. |
| `heuristic/maintainer-change` | 30 | Release | The release names a publisher that published no earlier release. Publishers compare case-insensitively. |
| `heuristic/install-scripts` | 15 | Release | The release runs install scripts, and it is the first release or the previous release did not. |

These are the exact reason texts:

| Rule | Reason |
| --- | --- |
| `heuristic/typosquat` | `resembles popular package "<name>" (<how>)` |
| `heuristic/new-package` | `first published <age> ago, under the <new-package-age> new-package age` |
| `heuristic/low-downloads` | `<count> downloads last week, below <low-downloads>` |
| `heuristic/maintainer-change` | `published by "<account>", who never published an earlier release` |
| `heuristic/install-scripts` | `first release runs install scripts`, or `runs install scripts, which the previous release <version> did not` |
| `heuristic/score` | `<package or release> scores <total> (<signal> <weight> + ...), reaching the <warn or block> threshold <threshold>` |

The release signals compare each release with the releases published before it. pkgwarden orders releases by publish time, not by version number. A release without a publish time gets no release signals. The first release in that order can never trigger `maintainer-change`, because there is no earlier publisher to compare against.

## What data each ecosystem provides

Registries publish different data, so not every signal works everywhere. A signal whose input is missing never fires.

| Signal | npm | PyPI | RubyGems | Go | Cargo |
| --- | --- | --- | --- | --- | --- |
| `typosquat` | Yes | Yes | Yes | Yes | Yes |
| `new-package` | Packument `time.created` | Earliest file upload | Earliest version `created_at` | Earliest `.info` time | Crate `created_at` |
| `low-downloads` | `api.npmjs.org` last-week count | `pypistats.org` `last_week` | All-time downloads divided by weeks since the first release | No data | crates.io `recent_downloads` divided by 13 |
| `maintainer-change` | Each version's `_npmUser.name` | No data | No data | No data | Each version's `published_by.login` |
| `install-scripts` | `preinstall`, `install`, or `postinstall` in the version's `scripts` | No data | No data | No data | No data |

Some of these inputs need a closer look:

- npm falls back to the packument's current `maintainers` list for a version without `_npmUser`.
- crates.io's `recent_downloads` counts 90 days, and 13 weeks is about 90 days.
- The RubyGems figure is an average over the gem's whole life, not a recent count.
- pkgwarden waits at most 5 seconds for a download count from the npm downloads API, pypistats, or the RubyGems gem API. If the lookup fails or is slow, the count is unknown and `low-downloads` does not fire. For PyPI, pkgwarden logs `pypi download count unavailable` at debug level.

## How the score turns into a decision

pkgwarden computes two scores.

- The package score adds up the package signals that fired. Those are `typosquat`, `new-package`, and `low-downloads`.
- A release score is the package score plus the release's own signals, `maintainer-change` and `install-scripts`.

Each score maps to a decision.

| Score | Decision |
| --- | --- |
| At or above `-heuristics-block` (default 70) | `block` |
| At or above `-heuristics-warn` (default 30) and below `-heuristics-block` | `warn` |
| Below `-heuristics-warn` | No finding |

A threshold of `0` or less is never reached, so `-heuristics-warn 0` turns warnings off. `-heuristics-warn` must not exceed `-heuristics-block`, or pkgwarden refuses to start. The highest possible score is 155, the sum of all five weights.

With the default thresholds, these combinations decide:

| Signals | Score | Decision |
| --- | --- | --- |
| `install-scripts` | 15 | No finding |
| `low-downloads` | 20 | No finding |
| `new-package` | 30 | `warn` |
| `maintainer-change` | 30 | `warn` |
| `new-package` + `low-downloads` | 50 | `warn` |
| `typosquat` | 60 | `warn` |
| `new-package` + `low-downloads` + `install-scripts` | 65 | `warn` |
| `typosquat` + `low-downloads` | 80 | `block` |
| `new-package` + `low-downloads` + `maintainer-change` | 80 | `block` |
| `typosquat` + `new-package` | 90 | `block` |

A package younger than 30 days therefore always warns, and a young package with few downloads blocks as soon as a release names a new publisher.

## Where heuristic findings appear

pkgwarden records each signal at the decision its total reached, followed by a `heuristic/score` finding that shows the sum.

- If the package score reaches a threshold, the package signals go on the package verdict. They then apply to every release and to the package's metadata. A package-level `block` refuses the whole package.
- If a release score reaches a stricter decision than the package score, that release restates every signal, package signals included, at its stricter decision.
- Otherwise a release lists only its own signals at its decision.

This verdict was captured on 2026-11-07. The crate `small_vec` resembles the popular `smallvec` and had 12 weekly downloads, so the package score reached the block threshold:

	$ curl -s 'http://127.0.0.1:18181/api/v1/check?ecosystem=cargo&name=small_vec'
	{
	  "ecosystem": "cargo",
	  "name": "small_vec",
	  "decision": "block",
	  "findings": [
	    {
	      "rule": "heuristic/typosquat",
	      "decision": "block",
	      "reason": "resembles popular package \"smallvec\" (differs only in separators)"
	    },
	    {
	      "rule": "heuristic/low-downloads",
	      "decision": "block",
	      "reason": "12 downloads last week, below 100"
	    },
	    {
	      "rule": "heuristic/score",
	      "decision": "block",
	      "reason": "package scores 80 (typosquat 60 + low-downloads 20), reaching the block threshold 70"
	    }
	  ]
	}

## Typosquat detection

Each ecosystem has a list of popular package names in `internal/policy/popular/<ecosystem>.txt`. The files are embedded in the binary at build time. A name that resembles a listed name without being on the list fires `heuristic/typosquat`.

### The popular lists

Each file holds one name per line. A `#` starts a comment. The lists hold packages people type into an install command, roughly ordered by downloads. They leave out deep transitive dependencies on purpose. Lockfiles name those exactly, so they are not typo targets, and their generic names would only add noise.

These are the current counts:

| File | Names |
| --- | --- |
| `cargo.txt` | 326 |
| `go.txt` | 393 |
| `npm.txt` | 394 |
| `pypi.txt` | 377 |
| `rubygems.txt` | 326 |

To count them again, run this from the repository root:

	grep -vc '^#' internal/policy/popular/*.txt

The lists are static. They change only when someone edits them and builds a new binary. See [Refresh the popular-package lists](development.md#refresh-the-popular-package-lists).

### How a name is compared

pkgwarden compares a name with the list in these steps:

1. It normalizes the name the way the registry does. npm and Cargo fold case, and Cargo also treats `_` as `-`. PyPI applies PEP 503, which folds case and turns runs of `-`, `_`, and `.` into one `-`. RubyGems and Go names stay as they are.
2. If the normalized name is on the list, the check stops. A listed package is never a typosquat.
3. It lower-cases the name and splits it on `/` into elements. An npm scoped name such as `@babel/core` has two elements. A Go module path such as `github.com/sirupsen/logrus` has three. Every other name has one.
4. It compares the name with each listed name that has the same number of elements. Exactly one element must differ.
5. It tests the differing element against the listed element. The first rule that matches decides, and the first listed name that matches wins.

The element tests run in this order:

| Test | How it reads in the reason | Example from the tests |
| --- | --- | --- |
| The elements are equal after `-`, `_`, and `.` are removed. | `differs only in separators` | `reactdom` resembles `react-dom` |
| The elements are equal after separators are removed and these look-alikes are replaced in both: `rn` with `m`, `vv` with `w`, `0` with `o`, `1` with `l`, `5` with `s`. | `differs only by look-alike characters` | `l0dash` resembles `lodash` |
| Both elements have at least 4 characters, and the optimal string alignment distance is 1. | `one edit away` | `lodahs` resembles `lodash` |
| Both elements have at least 4 characters, the listed element has more than 8 characters, and the distance is 2. | `two edits away` | `tyepscirpt` resembles `typescript` |

The optimal string alignment distance counts insertions, deletions, substitutions, and swaps of two adjacent characters. Each costs one.

Because only one element may differ, a Go typosquat is judged by the length of the owner, repository, or host that changed. `github.com/slrupsen/logrus` and `githuh.com/stretchr/testify` both fire. `golang.org/x/nett` does not. It is two edits from the listed `golang.org/x/text`, and `text` has too few characters to allow two.

### What is not flagged

The comparison leaves out these cases on purpose. Each one is a case in `TestTyposquat` in `internal/policy/typosquat_test.go`.

- A name that differs from a listed name only in letter case, such as `LoDash` or `github.com/Sirupsen/logrus`. Registries that care about case fold it, and GitHub resolves case variants to the same repository.
- A name the registry treats as the same package, such as `python_dateutil` for `python-dateutil` on PyPI or `serde-json` for `serde_json` on Cargo.
- A name with a different number of elements. The npm package `user-event` is not compared with `@testing-library/user-event`, and `github.com/sirupsen/logrus/v2` is not compared with `github.com/sirupsen/logrus`.
- An edit to an element shorter than 4 characters, such as `mss` or the `v9` in `github.com/go-redis/redis/v9`. Separator and look-alike changes still count for short elements.
- A name that adds words to a listed name, such as `lodash-utils-extra`.

## Flags that tune heuristics

| Flag | Default | Effect |
| --- | --- | --- |
| `-heuristics` | `true` | `-heuristics=false` turns every signal off. |
| `-heuristics-warn` | `30` | Score that adds a warning. `0` or less turns warnings off. |
| `-heuristics-block` | `70` | Score that blocks. Any value above 155 never blocks, so `-heuristics-block 1000` keeps warnings and stops blocking. `0` or less also turns blocking off, but only with `-heuristics-warn` at `0` or less, because the warn threshold must not exceed the block threshold. |
| `-new-package-age` | `720h` | Age below which `new-package` fires. `0` turns the signal off. |
| `-low-downloads` | `100` | Weekly count below which `low-downloads` fires. `0` turns the signal off. |

To accept one package that a heuristic keeps flagging, add it to [`-allow`](configuration.md#-allow). The allowlist also skips the cooldown and advisories for that package.

## Known false-positive patterns

These patterns can flag packages that are neither typosquats nor attacks. Each example was captured on 2026-11-07.

- Publisher rotation in npm teams. When the maintainers of an npm project take turns publishing, each maintainer's first release fires `maintainer-change`. `lodash@4.17.20` was published by `bnjmnt4n`, who had published no earlier lodash release, so it carried `published by "bnjmnt4n", who never published an earlier release` and a `release scores 30` warning.
- Long names near another long name. Names longer than 8 characters allow two edits. The gem `sidekiq-pro` warned with `resembles popular package "sidekiq-cron" (two edits away)`.
- Young packages. `new-package` alone reaches the default warn threshold, so every package younger than `-new-package-age` warns. A young package with few downloads blocks when a later release names a new publisher.
- npm versions without `_npmUser`. pkgwarden uses the packument's current `maintainers` list for such versions. A maintainer who joined later then counts as an earlier publisher, which hides a real change, and a maintainer who left later is missing, which can flag a later release.
- RubyGems lifetime averages. The RubyGems figure is a lifetime average, so a gem that was once popular keeps a high estimate, and a gem that was quiet for years and is now popular keeps a low one.
