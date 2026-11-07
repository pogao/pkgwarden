# pkgwarden documentation

Each page answers one kind of question. Start with how it works if you are new to pkgwarden, or with the package manager guide if you only need to set up a client.

| Page | Answers |
| --- | --- |
| [How pkgwarden works](how-it-works.md) | How a request flows, why pkgwarden filters metadata and refuses downloads, and what it does not do. |
| [Cooldown](cooldown.md) | Which releases are too new, how each ecosystem measures age, and how to change the wait. |
| [Advisories](advisories.md) | Which databases pkgwarden queries, which vulnerabilities block, and what happens when a lookup fails. |
| [Heuristics](heuristics.md) | Every suspicious-package signal, its weight, how scores become decisions, and how typosquats are detected. |
| [Point your package managers at pkgwarden](package-managers.md) | How to set up npm, pnpm, Yarn, pip, uv, Poetry, Bundler, gem, Go, and Cargo, and what each prints when a release is blocked. |
| [Configuration reference](configuration.md) | Every flag, its environment variable, default, accepted values, and startup errors, with example configurations. |
| [HTTP API reference](api.md) | The check endpoint, the health endpoint, the response headers, the 403 body, and every route each adapter serves. |
| [Deploy pkgwarden](deployment.md) | How to build and run the image, serve TLS, open egress, read the logs, and secure the service. |
| [Develop pkgwarden](development.md) | The code layout, the tests, the end-to-end script, adding an ecosystem, and refreshing the popular-package lists. |
