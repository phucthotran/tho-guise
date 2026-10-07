# Changelog

All notable changes to guise are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project does not yet follow strict semantic versioning — backwards-incompatible changes before 1.0 will be called out explicitly.

## [0.3.3] — 2026-10-07

### Changed

- **IMAP login failures now log a safe error detail** (`err=…`, plus `host:port`) on web and API auth paths — e.g. DNS/`gaierror`, `SSLError`, or Dovecot `AUTHENTICATIONFAILED` — without ever logging the password. Intended for Coolify/operator log panels when shell access is unavailable.

## [0.3.2] — 2026-10-07

### Changed

- **IMAP login username normalization (B1+B2).** Web form and API `Authentication` header now share `normalize_login_username`: short `alice` and full `alice@domain` both authenticate with a full-email IMAP LOGIN identity. Optional `GUISE_ALLOWED_DOMAINS` (comma-separated, case-insensitive; default `{GUISE_DOMAIN}`) permits alternate domains for IMAP auth; the session still stores the short local-part and alias targets remain on `GUISE_DOMAIN`.

## [0.3.1] — 2026-06-19

### Security

- **Container now runs as uid/gid 65532** (the distroless "nonroot" uid) instead of 1000. On a rootful Docker host without userns-remap a container uid maps 1:1 to the host uid; uid 1000 commonly belongs to a privileged human operator account, so a container escape from guise would have landed as that user. 65532 is a dedicated, unprivileged, non-overlapping uid. Packaging-only change — no application behavior change. Operators upgrading must `chown -R 65532:65532` the guise data volume before recreating the container.

## [0.3.0] — 2026-05-14

### Added

- **SimpleLogin-compatible HTTP API** at `POST /api/alias/random/new`. The endpoint accepts the same credentials as the web UI (mailbox short-username + IMAP password via the `Authentication` header) and returns `{"alias": "..."}` on success. Implemented for compatibility with Bitwarden's *Forwarded email alias → SimpleLogin (self-hosted server)* username generator; any other client that speaks the same subset works too. Full spec in [`docs/api.md`](docs/api.md).
- **Auto-labeling from `hostname` query parameter.** When Bitwarden sends `?hostname=www.netflix.com`, guise produces `g-<random>-netflix@…` using the Public Suffix List (`tldextract`) to extract the registered domain. Operator can disable per-instance with `GUISE_API_AUTOLABEL=0`.
- `tldextract==5.3.1` (BSD-3-Clause) added as a runtime dependency.

### Security

- API surface is exempt from CSRF (header-auth, no session cookies) but shares the IMAP-against-dovecot auth path, denylist, rate limiter (`30/min`), and audit-log events (`LOGIN_FAILED`/`ALIAS_CREATED` carry a `via=api` marker for filtering).

## [0.2.0] — 2026-05-13

### Added

- Per-row **copy-to-clipboard** button next to each alias in the *Managed by guise* and *Other aliases routing to you* sections. Uses `document.execCommand('copy')` for cross-context reliability.

### Changed

- **`docker-socket-proxy` sidecar is now the default install path** instead of a documented hardening option. New installs following the Quickstart get the restricted Docker-API surface by default — guise communicates with the host Docker daemon only through a sidecar that exposes only the `CONTAINERS` + `EXEC` API endpoints.
- README's Apache vhost example sets `RequestHeader set X-Forwarded-Proto "https"` so guise correctly detects HTTPS when behind the proxy.
- README's Quickstart leads with the prebuilt `ghcr.io/messelink/guise` image. The "build from source" path moves to its own subsection.
- GitHub Actions versions bumped to releases that support Node 24 (`actions/checkout@v6`, `actions/setup-python@v6`, `docker/setup-qemu-action@v4`, `docker/setup-buildx-action@v4`, `docker/login-action@v4`, `docker/metadata-action@v6`, `docker/build-push-action@v7`).

## [0.1.0] — 2026-05-12

Initial release. A small self-hosted Flask web app for managing per-recipient email aliases on a `docker-mailserver` instance, deployed as a sidecar inside the mailserver's compose project.

### Features

- Login via IMAP against the mailserver's dovecot — no password database
- Create labeled aliases with random 8-char hex prefix (e.g. `g-a3f82c11-netflix@example.com`)
- Per-user dashboard filtered by target email
- Delete aliases with a confirmation prompt; stronger prompt for aliases not created by guise
- Operator-configurable namespace tag, mail domain, denylist of usernames, IMAP host, and TLS verification mode

### Security

- CSRF protection on all unsafe-method routes (session-bound tokens validated in a before-request hook)
- Session cookies HttpOnly + SameSite=Lax + Secure (configurable); 12 h lifetime
- Open-redirect protection on the login `?next=` parameter
- App-layer rate limiting (flask-limiter): 20/min on `/login`, 30/min on `POST /aliases`, keyed on real client IP via `ProxyFix`
- IMAP TLS certificate validation enabled by default (`CERT_REQUIRED` against the system trust store or `GUISE_IMAP_CAFILE`); `GUISE_IMAP_INSECURE=1` escape hatch for genuinely trusted intra-bridge deployments
- Audit log entries for `LOGIN`, `LOGOUT`, `LOGIN_FAILED`, `LOGIN_DENIED`, `ALIAS_CREATED`, `ALIAS_DELETED`, `ALIAS_*_FAILED`, `ALIAS_DELETE_FORBIDDEN`
- Atomic secret-key creation (`O_EXCL` + mode 0o600)
- Strict shape validation on alias and target before subprocess invocation
- Generic flash messages on subprocess failures; detail logged server-side rather than leaked through the UI
- **`docker-socket-proxy` sidecar is the default install path** — guise communicates with the host Docker daemon only through a restricted proxy exposing only the `CONTAINERS` + `EXEC` API endpoints. An RCE in guise can run `setup alias …` inside mailserver and nothing else.

### Documented (not auto-applied) further hardening

- Read-only container filesystem with a tmpfs for `/tmp`
- Custom AppArmor / seccomp profile
- Base image / image-digest pinning instead of `:latest`
