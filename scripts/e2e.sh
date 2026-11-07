#!/usr/bin/env bash
# End-to-end check: builds the image, runs it, and drives the real package
# managers (npm, pip, bundler, go, cargo) through it against the public
# registries. Each ecosystem must install a normal package and refuse a
# known-bad release. Needs Docker and network access.
set -uo pipefail

cd "$(dirname "$0")/.."
image=pkgwarden:e2e
net=pkgwarden-e2e
url=http://pkgwarden:8080
host=http://127.0.0.1:18080
fails=0

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; fails=$((fails + 1)); }

expect_ok() {
	local name=$1 out
	shift
	if out=$("$@" 2>&1); then pass "$name"; else fail "$name"; tail -25 <<<"$out"; fi
}

expect_refused() {
	local name=$1 pattern=$2 out
	shift 2
	if out=$("$@" 2>&1); then
		fail "$name: succeeded"; tail -10 <<<"$out"
	elif grep -qiE "$pattern" <<<"$out"; then
		pass "$name"
	else
		fail "$name: failed without matching /$pattern/"; tail -25 <<<"$out"
	fi
}

expect_403() {
	local name=$1 path=$2 pattern=$3 body code
	body=$(curl -s -w '\n%{http_code}' "$host$path")
	code=$(tail -1 <<<"$body")
	body=$(sed '$d' <<<"$body")
	if [[ $code == 403 ]] && grep -qiE "$pattern" <<<"$body"; then
		pass "$name"; printf '     %s\n' "$(head -c 300 <<<"$body")"
	else
		fail "$name: HTTP $code"; head -c 600 <<<"$body"; echo
	fi
}

client() { docker run --rm --network "$net" "$@"; }

cleanup() {
	docker logs pkgwarden >e2e-pkgwarden.log 2>&1
	docker rm -f pkgwarden >/dev/null 2>&1
	docker network rm "$net" >/dev/null 2>&1
}
trap cleanup EXIT

docker build -q -t "$image" . >/dev/null || exit 1
docker network create "$net" >/dev/null
docker run -d --name pkgwarden --network "$net" -p 127.0.0.1:18080:8080 "$image" -log-level debug >/dev/null
for _ in $(seq 30); do curl -sf "$host/healthz" >/dev/null && break; sleep 1; done

echo "== npm"
expect_ok "npm install express" client node:22-alpine sh -c \
	"cd /tmp && npm init -y >/dev/null && npm install --no-audit --registry $url/npm/ express"
expect_refused "npm install lodash@4.17.20 (vulnerable)" "ETARGET|No matching version|403" client node:22-alpine sh -c \
	"cd /tmp && npm init -y >/dev/null && npm install --no-audit --registry $url/npm/ lodash@4.17.20"
expect_403 "npm tarball lodash@4.17.20 names the advisory" \
	/npm/lodash/-/lodash-4.17.20.tgz "vulnerability|GHSA"
expect_403 "npm unpublished malicious event-stream@3.3.6 is refused" \
	/npm/event-stream/-/event-stream-3.3.6.tgz "event-stream@3.3.6"
expect_ok "npm hides @types/node releases younger than 7 days" client node:22-alpine node -e "
	const week = 7 * 24 * 3600e3;
	const get = u => fetch(u, {headers: {accept: 'application/json'}}).then(r => r.json());
	(async () => {
		const up = await get('https://registry.npmjs.org/@types%2fnode');
		const young = Object.keys(up.versions).filter(v => Date.now() - Date.parse(up.time[v]) < week);
		const px = await get('$url/npm/@types%2fnode');
		const leaked = young.filter(v => v in px.versions);
		console.log('young upstream:', young.length, 'leaked:', leaked, 'proxy latest:', px['dist-tags'].latest);
		if (leaked.length || young.includes(px['dist-tags'].latest)) process.exit(1);
		if (!px.versions[px['dist-tags'].latest].dist.tarball.startsWith('$url/npm/')) process.exit(1);
	})().catch(e => { console.error(e); process.exit(1); });"

echo "== pypi"
expect_ok "pip download requests" client python:3.13-slim \
	pip download -q --no-deps -d /tmp/d --trusted-host pkgwarden --index-url "$url/pypi/simple/" requests
expect_ok "uv-style JSON simple API lists files" client python:3.13-slim python -c "
import json, urllib.request
r = urllib.request.Request('$url/pypi/simple/requests/', headers={'Accept': 'application/vnd.pypi.simple.v1+json'})
d = json.load(urllib.request.urlopen(r))
assert d['files'] and d['files'][0]['url'].startswith('$url/pypi/files/'), d['files'][:1]"
expect_refused "pip download urllib3==1.24.1 (vulnerable)" "No matching distribution|403" client python:3.13-slim \
	pip download -q --no-deps -d /tmp/d --trusted-host pkgwarden --index-url "$url/pypi/simple/" urllib3==1.24.1
expect_403 "pypi file urllib3 1.24.1 names the advisory" \
	/pypi/files/urllib3/1.24.1/urllib3-1.24.1-py2.py3-none-any.whl "vulnerability|GHSA|PYSEC|CVE"

echo "== go"
expect_ok "go get golang.org/x/text@latest" client -e GOPROXY="$url/go" golang:1.27-alpine sh -c \
	"mkdir /work && cd /work && go mod init example.com/e2e >/dev/null 2>&1 && go get golang.org/x/text@latest"
expect_refused "go get golang.org/x/text@v0.3.6 (vulnerable)" "403 Forbidden.*|pkgwarden blocked" client -e GOPROXY="$url/go" golang:1.27-alpine sh -c \
	"mkdir /work && cd /work && go mod init example.com/e2e >/dev/null 2>&1 && go get golang.org/x/text@v0.3.6"

echo "== cargo"
cargo_project() {
	cat <<-EOF
		mkdir -p /tmp/p/src /tmp/p/.cargo && cd /tmp/p && echo 'fn main() {}' > src/main.rs
		printf '[source.crates-io]\nreplace-with = "pkgwarden"\n[source.pkgwarden]\nregistry = "sparse+$url/cargo/index/"\n' > .cargo/config.toml
		printf '[package]\nname = "e2e"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\n%s\n' '$1' > Cargo.toml
		cargo fetch
	EOF
}
expect_ok "cargo fetch itoa through the proxy" client rust:1-slim sh -c "$(cargo_project 'itoa = "1"') 2>&1 | tee /dev/stderr | grep -q 'pkgwarden'"
expect_refused "cargo fetch smallvec =1.6.0 (vulnerable)" "failed to select a version" \
	client rust:1-slim sh -c "$(cargo_project 'smallvec = "=1.6.0"')"
expect_403 "crate smallvec 1.6.0 names the advisory" /cargo/api/v1/crates/smallvec/1.6.0/download "vulnerability|GHSA|RUSTSEC"

echo "== rubygems"
bundle_project() {
	cat <<-EOF
		mkdir -p /tmp/g && cd /tmp/g
		printf 'source "https://rubygems.org"\ngem %s\n' '$1' > Gemfile
		bundle config set --local mirror.https://rubygems.org $url/rubygems
		bundle config set --local path vendor/bundle
		bundle install
	EOF
}
expect_ok "bundle install rack" client ruby:3.3-slim sh -c "$(bundle_project '"rack", "~> 3.0"')"
expect_refused "bundle install rack 2.2.3 (vulnerable)" "Could not find|403|pkgwarden" \
	client ruby:3.3-slim sh -c "$(bundle_project '"rack", "= 2.2.3"')"
expect_403 "gem rack 2.2.3 names the advisory" /rubygems/gems/rack-2.2.3.gem "vulnerability|GHSA|CVE"

echo "== check API"
curl -s "$host/api/v1/check?ecosystem=npm&name=lodash&version=4.17.20" | head -c 600; echo

echo
if ((fails)); then echo "$fails check(s) failed; proxy log in e2e-pkgwarden.log"; exit 1; fi
echo "all checks passed"
