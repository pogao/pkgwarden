# Point your package managers at pkgwarden

This guide configures each supported client to install through pkgwarden. It then shows what each ecosystem filters, what passes through, and what the client prints when pkgwarden blocks a release.

The setup commands assume pkgwarden runs at `http://localhost:8080`. Replace that with your `-public-url` if pkgwarden runs elsewhere. The sample outputs were captured on 2026-11-07 against an instance at `http://127.0.0.1:18181`.

When a client reports that no version matches and you expect one, ask pkgwarden why:

	curl 'http://localhost:8080/api/v1/check?ecosystem=npm&name=lodash&version=4.17.20'

See [the check endpoint](api.md#get-apiv1check) for the response format.

## npm, pnpm, and Yarn

### Configure the client

For npm, set the registry for your user:

	npm config set registry http://localhost:8080/npm/

To set it for one project only, put this line in the project's `.npmrc`:

	registry=http://localhost:8080/npm/

For pnpm, run this:

	pnpm config set registry http://localhost:8080/npm/

For Yarn 1, run this:

	yarn config set registry http://localhost:8080/npm/

For Yarn 2 and later, add these lines to `.yarnrc.yml`. Yarn refuses plain HTTP to hosts outside `unsafeHttpWhitelist`, so drop that line if pkgwarden serves HTTPS.

```yaml
npmRegistryServer: "http://localhost:8080/npm/"
unsafeHttpWhitelist:
  - localhost
```

npm also sends lockfile installs through pkgwarden. A `package-lock.json` entry resolved at `https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz` was fetched from `http://127.0.0.1:18181/npm/lodash/-/lodash-4.17.20.tgz` by `npm ci --registry http://127.0.0.1:18181/npm/`. Yarn 1 writes pkgwarden's tarball URLs into `yarn.lock`.

### What pkgwarden filters

- The packument at `/npm/<name>` loses every blocked version from `versions` and `time`. Its tarball links point at pkgwarden.
- The `latest` tag moves to the newest allowed stable version that is not newer than the version it pointed at. Other tags on blocked versions are removed.
- A version manifest at `/npm/<name>/<version>` comes from the filtered packument.
- A tarball download is checked against the version whose packument entry links to it, not the version in its file name.
- `npm dist-tag ls` gets the tags of the filtered packument.
- `npm audit` requests and the other registry endpoints under `/npm/-/`, such as `npm search`, pass through to `registry.npmjs.org` unchanged. Any other path gets 404.
- Publishing and every other write method get 405. Publish to the public registry directly.

### What you see when a release is blocked

If you name a blocked version, npm cannot find it in the filtered packument:

	$ npm install --no-audit --registry http://127.0.0.1:18181/npm/ lodash@4.17.20
	npm error code ETARGET
	npm error notarget No matching version found for lodash@4.17.20.
	npm error notarget In most cases you or one of your dependencies are requesting a package version that doesn't exist.

Yarn 1 reports the same case like this:

	error Couldn't find any versions for "lodash" that matches "4.17.20"

If npm fetches the tarball directly, such as from a lockfile, it prints pkgwarden's reason. This output is trimmed after the second line:

	$ npm install --no-audit --registry http://127.0.0.1:18181/npm/ http://127.0.0.1:18181/npm/lodash/-/lodash-4.17.20.tgz
	npm error code E403
	npm error 403 403 Forbidden - GET http://127.0.0.1:18181/npm/lodash/-/lodash-4.17.20.tgz - pkgwarden blocked npm/lodash@4.17.20: advisory/vulnerability: GHSA-35jh-r3h4-6jhm (high vulnerability, via osv): Command Injection in lodash https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm; advisory/vulnerability: GHSA-r5fr-rjxr-66jc (high vulnerability, via osv): lodash vulnerable to Code Injection via `_.template` imports key names https://osv... (request 0d43614cae40e59f3c498ff91116a7be)
	...

If the whole package is blocked, or every version of it is, the packument request itself gets the 403, and npm prints the reason in the same form.

## pip, uv, and Poetry

### Configure the client

For pip, set the index for your user:

	pip config set global.index-url http://localhost:8080/pypi/simple/

pip accepts plain HTTP only from `localhost`, `127.0.0.0/8`, and `::1`. For any other host name, also mark the host as trusted:

	pip config set global.trusted-host pkgwarden.internal

For uv, set the default index in the environment:

	export UV_DEFAULT_INDEX=http://localhost:8080/pypi/simple/

To set it for one uv project, add this to `pyproject.toml`:

```toml
[[tool.uv.index]]
name = "pkgwarden"
url = "http://localhost:8080/pypi/simple/"
default = true
```

For Poetry, add pkgwarden as the primary source of the project:

	poetry source add --priority=primary pkgwarden http://localhost:8080/pypi/simple/

### What pkgwarden filters

- The project page at `/pypi/simple/<project>/` lists only the files of allowed releases. pkgwarden builds it from the PyPI JSON API and serves PEP 691 JSON or PEP 503 HTML, as the client's `Accept` header asks. It keeps hashes, `requires-python`, yanked flags, and PEP 658 metadata links.
- A file download at `/pypi/files/<project>/<version>/<file>` is checked against its release. pkgwarden serves it only from the URL PyPI's metadata records for that file.
- A project name that is not PEP 503 normalized, or a page URL without the trailing `/`, gets a 301 to the normalized URL.
- The root index at `/pypi/simple/` passes through, but its links do not work through pkgwarden. pip and uv do not need it to install.

### What you see when a release is blocked

pip and uv see only the allowed releases:

	$ pip3 download -q --no-deps --no-cache-dir -d /tmp/d --index-url http://127.0.0.1:18181/pypi/simple/ urllib3==1.24.1
	ERROR: Could not find a version that satisfies the requirement urllib3==1.24.1 (from versions: 2.8.0)
	ERROR: No matching distribution found for urllib3==1.24.1

	$ uv pip install --dry-run --python venv --index-url http://127.0.0.1:18181/pypi/simple/ urllib3==1.24.1
	Using Python 3.13.3 environment at: venv
	error: No solution found when resolving dependencies
	  cause: Because there is no version of urllib3==1.24.1 and you require urllib3==1.24.1, we can conclude that your requirements are unsatisfiable.

If the whole package is blocked, the project page gets the 403. pip then reports `(from versions: none)`. uv adds a hint that names the 403 but not the reason:

	hint: An index (http://127.0.0.1:18182/pypi/simple/) returned a 403 Forbidden error. Check that the index URL is correct and the credentials are valid.

pip does not print the body of a 403 on a file, so a direct download shows only the status. This output is trimmed to its first two lines:

	$ pip3 download --no-deps --no-cache-dir -d /tmp/d http://127.0.0.1:18181/pypi/files/urllib3/1.24.1/urllib3-1.24.1-py2.py3-none-any.whl
	Collecting urllib3==1.24.1
	  ERROR: HTTP error 403 while getting http://127.0.0.1:18181/pypi/files/urllib3/1.24.1/urllib3-1.24.1-py2.py3-none-any.whl
	...

## Bundler and gem

### Configure the client

For Bundler, mirror rubygems.org through pkgwarden. Your Gemfile keeps `source "https://rubygems.org"`.

	bundle config set mirror.https://rubygems.org http://localhost:8080/rubygems

For the gem command, replace the default source:

	gem sources --add http://localhost:8080/rubygems/ --remove https://rubygems.org/

### What pkgwarden filters

- The compact index file at `/rubygems/info/<gem>` loses the lines of blocked versions. Bundler and `gem install` resolve against it.
- A gem blocked at package level gets an info file that holds only `---`, so the client sees a gem with no versions. [How pkgwarden works](how-it-works.md#a-fully-blocked-gem-gets-an-empty-info-file) explains why it is not a 403.
- Downloads of `.gem` files and of `quick/Marshal.4.8/*.gemspec.rz` files are checked against their version. A `.gem` file is checked at both of its rubygems.org URLs, `/gems/<file>.gem` and `/downloads/<file>.gem`.
- A trailing slash or an extra segment on one of these paths, such as `/info/<gem>/`, gets 404. rubygems.org answers `/info/<gem>/` with the unfiltered file.
- Every other path passes through, including `/versions`, `/names`, and the legacy indexes such as `specs.4.8.gz`.

The legacy indexes are not filtered. `gem fetch` and `gem list -r` read them, so they can pick a blocked version and then fail on its 403. Bundler and `gem install` use the filtered compact index.

### What you see when a release is blocked

Bundler names the original source, not the mirror. This output comes from a Gemfile that asks for `gem "rack", "= 2.2.3"`, trimmed at both ends:

	$ bundle lock
	...
	Fetching gem metadata from http://127.0.0.1:18181/rubygems/.
	Could not find gem 'rack (= 2.2.3)' in rubygems repository https://rubygems.org/
	or installed locally.

	The source contains the following gems matching 'rack':
	  * rack-2.2.23
	  * rack-2.2.24
	...

	$ gem install rack -v 2.2.3 --clear-sources --source http://127.0.0.1:18181/rubygems/ -i /tmp/gems --no-document
	ERROR:  Could not find a valid gem 'rack' (= 2.2.3) in any repository
	ERROR:  Possible alternatives: Rack

`gem fetch` reads the unfiltered legacy index and reaches the 403:

	$ gem fetch rack -v 2.2.3 --clear-sources --source http://127.0.0.1:18181/rubygems/
	ERROR:  Could not find a valid gem 'rack' (= 2.2.3), here is why:
	          Unable to download data from http://127.0.0.1:18181/rubygems/ - bad response Forbidden 403 (http://127.0.0.1:18181/rubygems/quick/Marshal.4.8/rack-2.2.3.gemspec.rz)

None of these clients print pkgwarden's reason. Use the check endpoint to see it.

## Go

### Configure the client

Set `GOPROXY` to pkgwarden alone:

	go env -w GOPROXY=http://localhost:8080/go

Do not add `,direct` or `|direct` after pkgwarden. With `,direct`, the go command goes to the origin repository whenever pkgwarden answers 404 or 410, which it does for a module that does not exist upstream. With `|direct`, it falls back on any error, including pkgwarden's 403.

Modules that match `GOPRIVATE` or `GONOPROXY` skip every proxy, so pkgwarden never checks them.

The go command checks downloads against the checksum database at `sum.golang.org`. pkgwarden does not serve it, because `proxy.golang.org` answers 404 for `/sumdb/`, so the go command contacts `sum.golang.org` itself. Your clients need network access to it. If they cannot have it, set `GOSUMDB=off` or list your modules in `GONOSUMDB`. Both turn off that verification.

### What pkgwarden filters

- The version list at `/go/<module>/@v/list` loses blocked versions. `proxy.golang.org` lists some versions whose `.info` file answers 404. Their publish time is unknown, so the cooldown blocks them and the rest of the list is served.
- `/go/<module>/@latest` answers with the newest allowed release, or the newest allowed prerelease when no release is allowed.
- `.info` and `.mod` files pass through for every version, because minimal version selection reads the `go.mod` of versions it will not select.
- A `.zip` download is checked against its version. The version must be canonical, so `v1.6.zip` gets a 400 and never reaches upstream. A pseudo-version gets assessed even though no list includes it. A version that no list includes and that has no `.info` file gets an `unknown-release` block.

### What you see when a release is blocked

The go command prints the 403 body as `server response:`:

	$ GOPROXY=http://127.0.0.1:18181/go go get golang.org/x/text@v0.3.6
	go: downloading golang.org/x/text v0.3.6
	go: golang.org/x/text@v0.3.6: reading http://127.0.0.1:18181/go/golang.org/x/text/@v/v0.3.6.zip: 403 Forbidden
		server response: pkgwarden blocked go/golang.org/x/text@v0.3.6: advisory/vulnerability: GHSA-69ch-w2m2-3vjp (high vulnerability, via osv): golang.org/x/text/language Denial of service via crafted Accept-Language header ht...; advisory/vulnerability: GHSA-ppp9-7jff-5vj2 (high vulnerability, via osv): golang.org/x/text/language Out-of-bounds Read vulnerability https://osv.dev/vulner... (request 3e91355d824c4722c4475314da6064de)

Each reason in the message is cut to 160 bytes, which is where the `...` comes from. The go command keeps at most 8 lines and 648 bytes of a server response and replaces the rest with `[Truncated: too long.]`. The limits are in `cmd/go/internal/web/api.go`. pkgwarden caps its messages to stay inside them.

If the whole module is blocked, the version list request gets the 403:

	go: github.com/google/uuid@latest: module github.com/google/uuid: reading http://127.0.0.1:18182/go/github.com/google/uuid/@v/list: 403 Forbidden
		server response: pkgwarden blocked go/github.com/google/uuid: advisory-lookup: advisory lookup failed: osv lookup go/github.com/google/uuid: Post "http://127.0.0.1:1/v1/query": dial tcp 127.0.0.1:1: connect: connection ... (request 84afae7698659e41e9e62319ac3cf665)

That output came from an instance whose `-osv-url` pointed at a closed port.

## Cargo

### Configure the client

Add these lines to `.cargo/config.toml` in your project, or to `$CARGO_HOME/config.toml` for every project:

```toml
[source.crates-io]
replace-with = "pkgwarden"

[source.pkgwarden]
registry = "sparse+http://localhost:8080/cargo/index/"
```

Commands that use the crates.io web API, such as `cargo search` and `cargo publish`, still go to `https://crates.io`. pkgwarden's `config.json` names it as the `api` URL.

### What pkgwarden filters

- Each index file at `/cargo/index/<prefix>/<crate>` loses the lines of blocked versions. The other lines are kept byte for byte.
- `config.json` points crate downloads at `/cargo/api/v1/crates/<crate>/<version>/download`, and each download is checked against its version.
- pkgwarden looks crates up through the crates.io API, which matches names case-insensitively and treats `-` and `_` alike. Index paths must still be the lower-case form Cargo derives.

### What you see when a release is blocked

Cargo sees only the allowed versions. This output is trimmed after the first four lines:

	$ cargo fetch
	    Updating `pkgwarden` index
	error: failed to select a version for the requirement `smallvec = "=1.6.0"`
	candidate versions found which didn't match: 2.0.0-beta.4, 2.0.0-beta.3, 2.0.0-beta.2, ...
	location searched: `pkgwarden` index (which is replacing registry `crates-io`)
	...

A direct download gets the 403 with the reason:

	$ curl -s http://127.0.0.1:18181/cargo/api/v1/crates/smallvec/1.6.0/download
	pkgwarden blocked cargo/smallvec@1.6.0: advisory/vulnerability: GHSA-43w2-9j62-hq99 (critical vulnerability, via osv): Buffer overflow in SmallVec::insert_many https://osv.dev/vulnerability/GHSA-43... (request f3b81df0468fbbea48d308745598b8ed)

## Warnings

A release with a `warn` verdict installs normally. No client shows the warning. pkgwarden sends it in the `X-Pkgwarden-Warning` response header and logs it as `serving with warnings`. See [Read the logs](deployment.md#read-the-logs).
