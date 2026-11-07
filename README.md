# pkgwarden

pkgwarden is a package proxy for npm, PyPI, RubyGems, Go modules, and Cargo. It sits between your package managers and the public registries. It refuses releases that are too new, known to be malicious or vulnerable, or that look suspicious.

Package managers keep working normally through it. pkgwarden removes blocked versions from the metadata it serves, so a resolver picks the newest allowed version on its own. A direct download of a blocked version gets HTTP 403, and the client prints the reason:

```
npm error code E403
npm error 403 403 Forbidden - GET http://localhost:8080/npm/lodash/-/lodash-4.17.20.tgz - pkgwarden blocked npm/lodash@4.17.20: advisory: GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
```

## What it checks

| Check | Default | Effect |
| --- | --- | --- |
| Cooldown | 7 days | Releases younger than the cooldown are hidden. A release with no known publish time is blocked. |
| Malicious packages | always on | Releases listed as malicious (OSV `MAL-` entries, GHSA `malware`, the OpenSSF malicious-packages dataset) are blocked. |
| Known vulnerabilities | block at high | Releases inside an advisory's affected range are blocked when the vulnerability is rated high or critical. Medium, low, and unrated ones warn. `-block-severity` sets the threshold. |
| Heuristics | on | Suspicious signals add to a score. A score of 30 warns and 70 blocks. |

The heuristic signals and their weights:

| Signal | Weight | Fires when |
| --- | --- | --- |
| `typosquat` | 60 | The name is one or two edits, a separator change, or a look-alike character away from a popular package in the same ecosystem. |
| `new-package` | 30 | The package was first published less than `-new-package-age` ago (30 days). |
| `low-downloads` | 20 | Weekly downloads are below `-low-downloads` (100). |
| `maintainer-change` | 30 | A release is published by an account that published no earlier release. |
| `install-scripts` | 15 | An npm release adds `preinstall`, `install`, or `postinstall` scripts that the previous release did not have. |

Registries do not all publish the same data, so some signals do not apply everywhere. Go has no download counts or publisher data. PyPI and RubyGems have no per-release publisher. RubyGems weekly downloads are estimated from the all-time count.

A warning does not stop the download. pkgwarden logs it and sends it in the `X-Pkgwarden-Warning` response header.

## Advisory sources

- OSV (`api.osv.dev`) is always queried. It already imports the GitHub Advisory Database and the OpenSSF malicious-packages dataset, so it covers all three on its own.
- The GitHub Advisory Database is also queried directly when `GITHUB_TOKEN` (or `-ghsa-token`) is set.
- The OpenSSF malicious-packages dataset is synced to a local index when `-openssf` is set. Each refresh downloads about 300 MB, so it is off by default.

A vulnerability's rating comes from the database's own rating. When a record has none, pkgwarden computes the base score of its CVSS v3 vector. A record with neither is unrated.

pkgwarden merges entries from all sources by ID and alias, and keeps the highest rating any of them gives. It caches each lookup for `-advisory-ttl` (1 hour). If a source cannot be reached, the package is blocked, unless you set `-fail-open`.

## Run it

```sh
docker build -t pkgwarden .
docker run -p 8080:8080 pkgwarden
```

To run it from source:

```sh
go run ./cmd/pkgwarden -listen :8080
```

Behind a reverse proxy, set `-public-url https://pkgwarden.example.com` so rewritten download links use the public address.

## Point your package managers at it

The examples assume pkgwarden runs at `http://localhost:8080`.

**npm, pnpm, and Yarn.**

```sh
npm config set registry http://localhost:8080/npm/
```

**pip and uv.**

```sh
pip config set global.index-url http://localhost:8080/pypi/simple/
pip config set global.trusted-host localhost   # only needed for plain HTTP
export UV_INDEX_URL=http://localhost:8080/pypi/simple/
```

**Bundler and RubyGems.**

```sh
bundle config set mirror.https://rubygems.org http://localhost:8080/rubygems
gem sources --add http://localhost:8080/rubygems/ --remove https://rubygems.org/
```

**Go.** Do not add `,direct` after pkgwarden. pkgwarden answers a block with 403 so the go command stops, but a `direct` entry would still be used for modules the proxy reports as missing.

```sh
go env -w GOPROXY=http://localhost:8080/go
```

**Cargo.** Add this to `.cargo/config.toml` or `$CARGO_HOME/config.toml`:

```toml
[source.crates-io]
replace-with = "pkgwarden"

[source.pkgwarden]
registry = "sparse+http://localhost:8080/cargo/index/"
```

## Ask why a release is blocked

`GET /api/v1/check` returns the verdict without downloading anything:

```sh
curl 'http://localhost:8080/api/v1/check?ecosystem=npm&name=lodash&version=4.17.20'
```

```json
{
  "ecosystem": "npm",
  "name": "lodash",
  "version": "4.17.20",
  "decision": "block",
  "findings": [
    {
      "rule": "advisory",
      "decision": "block",
      "reason": "GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"
    },
    {
      "rule": "advisory",
      "decision": "warn",
      "reason": "GHSA-29mw-wpgm-hmr9 (medium vulnerability, via osv): Regular Expression Denial of Service (ReDoS) in lodash https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9"
    },
    ...
  ]
}
```

Leave out `version` to see findings that apply to the whole package. `ecosystem` is one of `npm`, `pypi`, `rubygems`, `go`, or `cargo`. `/healthz` returns `ok`.

## Configuration

Every flag can also be set with an environment variable named `PKGWARDEN_<FLAG>`, in upper case with dashes changed to underscores. For example, `-cooldown` becomes `PKGWARDEN_COOLDOWN`. A command-line flag wins over the environment.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `:8080` | Address to listen on. |
| `-public-url` | derived per request | External base URL used in rewritten download links. |
| `-cooldown` | `168h` | Minimum release age. `0` turns it off. |
| `-block-severity` | `high` | Lowest vulnerability rating that blocks: `low`, `medium`, `high`, `critical`, or `none`. Lower-rated and unrated vulnerabilities warn. `none` never blocks for vulnerabilities. Malicious releases always block. |
| `-fail-open` | `false` | Serve packages when advisory sources are unreachable. |
| `-allow` | empty | Comma-separated `ecosystem:name` packages exempt from every check, such as `npm:my-internal-lib`. |
| `-heuristics` | `true` | Score heuristic signals. |
| `-heuristics-warn` | `30` | Score that adds a warning. |
| `-heuristics-block` | `70` | Score that blocks. |
| `-new-package-age` | `720h` | Age below which a package counts as new. |
| `-low-downloads` | `100` | Weekly downloads below which a package counts as unpopular. |
| `-osv-url` | `https://api.osv.dev` | OSV API base URL. |
| `-ghsa-token` | `$GITHUB_TOKEN` | Enables direct GitHub Advisory Database lookups. |
| `-openssf` | `false` | Sync the OpenSSF malicious-packages dataset. |
| `-openssf-refresh` | `6h` | OpenSSF refresh interval. |
| `-metadata-ttl` | `5m` | How long upstream metadata is cached. |
| `-advisory-ttl` | `1h` | How long advisory lookups are cached. |
| `-log-level` | `info` | `debug`, `info`, `warn`, or `error`. Logs are JSON on stderr. |

## Known limits

- pkgwarden does not store artifacts. Every allowed download streams from the upstream registry.
- When every release of a package is blocked, pip, uv, cargo, and Bundler report that no version matches, without pkgwarden's reason. Use `/api/v1/check` to see the reason. A direct download still gets the 403 with the reason.
- RubyGems legacy indexes (`specs.4.8.gz` and related files) pass through unfiltered. `gem fetch` and `gem list -r` can pick a blocked version and then fail on its 403. Bundler and `gem install` use the filtered compact index.
- The Go adapter does not serve the checksum database, because proxy.golang.org does not. The go command reads `sum.golang.org` directly, so clients must be able to reach it.
- The popular-package lists used for typosquatting live in `internal/policy/popular/`. They are static, so refresh them now and then.

## Development

```sh
go test -race ./...
./scripts/e2e.sh   # builds the image and drives real npm, pip, bundler, go and cargo through it; needs Docker and network access
```

The code is laid out as follows:

- `internal/proxy/<ecosystem>` translates one registry protocol to and from `policy.Package`.
- `internal/policy` holds the engine: cooldown, advisories, heuristics, and typosquatting.
- `internal/advisory` holds the OSV, GHSA, and OpenSSF sources and their merging and caching.
- `internal/version` orders versions with each ecosystem's rules: SemVer, PEP 440, and Gem::Version.
