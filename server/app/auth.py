import hashlib
import hmac
import imaplib
import re
import secrets
import ssl
from dataclasses import dataclass
from functools import wraps
from typing import Callable, Literal
from urllib.parse import urlparse

from flask import Flask, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from .config import Config
from .extensions import limiter


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class LoginIdentity:
    """Normalized identity shared by web login and API auth.

    ``username`` is the short local-part stored in the session and used for
    alias targeting (``{username}@{GUISE_DOMAIN}``). ``imap_username`` is the
    full email address passed to Dovecot IMAP LOGIN — never short-only.
    """

    username: str
    imap_username: str


@dataclass(frozen=True)
class NormalizeError:
    reason: Literal["empty", "bad_username", "unknown_domain"]
    message: str


def csrf_token() -> str:
    """Return the per-session CSRF token, creating it on first access."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _csrf_valid(submitted: str | None, expected: str | None) -> bool:
    if not submitted or not expected:
        return False
    return secrets.compare_digest(submitted, expected)


def validate_csrf() -> None:
    """Before-request hook: 400 on unsafe methods with missing/wrong token.

    Skipped for /api/* — that surface uses header-based auth (no session
    cookie), so CSRF doesn't apply.
    """
    if request.method not in UNSAFE_METHODS:
        return
    if request.path.startswith("/api/"):
        return
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not _csrf_valid(submitted, expected):
        abort(400, description="Invalid CSRF token")


def _safe_next_url(raw: str | None, default: str) -> str:
    """Reject open-redirect attempts. Only same-site paths starting with a
    single '/' are permitted; '//host' and '/\\host' are rejected.
    """
    if not raw:
        return default
    if not raw.startswith("/"):
        return default
    if raw.startswith(("//", "/\\")):
        return default
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return default
    return raw


def normalize_login_username(raw: str, config: Config) -> LoginIdentity | NormalizeError:
    """Parse a login identifier into session short-name + full IMAP username.

    Accepts short ``alice`` or full ``alice@domain`` forms. Short names always
    authenticate as ``alice@{GUISE_DOMAIN}``. Full addresses are allowed only
    when the domain is in ``config.allowed_domains`` (case-insensitive); the
    IMAP LOGIN uses that full address, while the session still stores the
    local-part for alias targeting on ``GUISE_DOMAIN``.

    Note: aliases are always created as ``{local}@{GUISE_DOMAIN}``. Logging in
    with an allowlisted alternate domain authenticates that mailbox over IMAP
    but does not retarget alias CRUD to the alternate domain.
    """
    if not raw:
        return NormalizeError("empty", "Username required.")

    if "@" not in raw:
        local = raw
        imap_username = f"{local}@{config.domain}"
    else:
        local, _, domain_part = raw.partition("@")
        if domain_part.lower() not in config.allowed_domains:
            allowed = ", ".join(sorted(config.allowed_domains))
            return NormalizeError(
                "unknown_domain",
                f"Domain not allowed for login. Permitted domains: {allowed}.",
            )
        # Preserve the configured primary domain's canonical casing when it
        # matches; otherwise keep the (already lowercased) typed domain.
        if domain_part.lower() == config.domain.lower():
            imap_domain = config.domain
        else:
            imap_domain = domain_part.lower()
        imap_username = f"{local}@{imap_domain}"

    if not USERNAME_RE.match(local):
        return NormalizeError("bad_username", "Invalid username.")

    return LoginIdentity(username=local, imap_username=imap_username)


def build_imap_username(username: str, config: Config) -> str:
    """Build the full IMAP LOGIN identity for a short session username.

    Prefer ``normalize_login_username`` for raw form/header input; use this
    only when you already have a validated short local-part.
    """
    return f"{username}@{config.domain}"


def password_fingerprint(password: str, secret_key: str) -> str:
    """Short HMAC fingerprint for comparing web vs API passwords in logs.

    Never log the password itself. Same password + same instance secret_key
    always yields the same ``pass_fp``; Bitwarden vs web mismatches show up
    as different fingerprints.
    """
    return hmac.new(
        secret_key.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:12]


@dataclass(frozen=True)
class ImapAuthResult:
    """Outcome of an IMAP LOGIN attempt. ``error`` is safe to write to logs
    (never includes the password)."""

    ok: bool
    error: str | None = None


def _imap_error_detail(exc: BaseException, config: Config) -> str:
    """Compact, password-free error string for Coolify/operator logs."""
    msg = " ".join(str(exc).split())
    if len(msg) > 160:
        msg = msg[:160] + "..."
    return f"{type(exc).__name__}: {msg} host={config.imap_host}:{config.imap_port}"


def _imap_check(imap_username: str, password: str, config: Config) -> ImapAuthResult:
    """Authenticate against the mailserver's dovecot via IMAPS.

    ``imap_username`` must already be a full email address (see
    ``normalize_login_username`` / ``build_imap_username``).

    Cert validation is on by default (CERT_REQUIRED against the system trust
    store, or `GUISE_IMAP_CAFILE` if set). Hostname verification is off because
    we typically reach the mailserver by its Docker network name (`mailserver`),
    not by the cert's CN (the public mail hostname).

    `GUISE_IMAP_INSECURE=1` disables all TLS verification — only use if you
    genuinely need it and understand the MITM exposure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    if config.imap_insecure:
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if config.imap_cafile:
            ctx.load_verify_locations(cafile=config.imap_cafile)
    try:
        with imaplib.IMAP4_SSL(
            config.imap_host,
            config.imap_port,
            ssl_context=ctx,
            timeout=config.imap_timeout,
        ) as imap:
            imap.login(imap_username, password)
            try:
                imap.logout()
            except Exception:
                pass
        return ImapAuthResult(ok=True)
    except imaplib.IMAP4.error as exc:
        return ImapAuthResult(ok=False, error=_imap_error_detail(exc, config))
    except OSError as exc:
        # ssl.SSLError is a subclass of OSError, so it's covered here too.
        return ImapAuthResult(ok=False, error=_imap_error_detail(exc, config))
    except Exception as exc:  # noqa: BLE001 — surface unexpected failures in logs
        return ImapAuthResult(ok=False, error=_imap_error_detail(exc, config))


def verify_credentials(raw_username: str, password: str, config: Config) -> str | None:
    """Normalize + validate + IMAP-check. Returns short username on success."""
    username, _error = check_credentials(raw_username, password, config)
    return username


def check_credentials(
    raw_username: str, password: str, config: Config,
) -> tuple[str | None, str | None]:
    """Normalize + validate + IMAP-check.

    Returns ``(short_username, None)`` on success, or ``(None, error_detail)``
    on failure. ``error_detail`` is safe for logs (no password). Shared by the
    web login flow and the API auth path so they accept the same identities.
    """
    if not password:
        return None, "password_missing"
    identity = normalize_login_username(raw_username, config)
    if isinstance(identity, NormalizeError):
        return None, f"normalize:{identity.reason}"
    if identity.username in config.denied_users:
        return None, "denied_user"
    result = _imap_check(identity.imap_username, password, config)
    if result.ok:
        return identity.username, None
    return None, result.error or "imap_auth_failed"


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login", next=request.path))
        g.user = session["user"]
        g.target_email = build_imap_username(g.user, current_app.config["GUISE"])
        return view(*args, **kwargs)
    return wrapped


def register(app: Flask) -> None:
    from flask import Blueprint
    bp = Blueprint("auth", __name__)

    @bp.route("/login", methods=["GET", "POST"])
    @limiter.limit("20 per minute")
    def login():
        config: Config = current_app.config["GUISE"]
        if request.method == "POST":
            raw = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""
            identity = normalize_login_username(raw, config)
            if isinstance(identity, NormalizeError):
                flash(identity.message, "error")
            elif identity.username in config.denied_users:
                current_app.logger.warning(
                    "LOGIN_DENIED user=%s ip=%s", identity.username, request.remote_addr,
                )
                flash("This account is not permitted to use guise.", "error")
            elif not password:
                flash("Password required.", "error")
            else:
                imap_result = _imap_check(identity.imap_username, password, config)
                pass_fp = password_fingerprint(password, config.secret_key)
                if imap_result.ok:
                    session.clear()
                    session["user"] = identity.username
                    session.permanent = True
                    current_app.logger.info(
                        "LOGIN user=%s imap=%s ip=%s pass_len=%d pass_fp=%s",
                        identity.username,
                        identity.imap_username,
                        request.remote_addr,
                        len(password),
                        pass_fp,
                    )
                    default_next = url_for("main.index")
                    next_url = _safe_next_url(request.args.get("next"), default_next)
                    return redirect(next_url)
                current_app.logger.warning(
                    "LOGIN_FAILED user=%s imap=%s ip=%s host=%s:%s pass_len=%d pass_fp=%s err=%s",
                    identity.username,
                    identity.imap_username,
                    request.remote_addr,
                    config.imap_host,
                    config.imap_port,
                    len(password),
                    pass_fp,
                    imap_result.error,
                )
                flash("Login failed.", "error")
        return render_template("login.html")

    @bp.route("/logout", methods=["POST"])
    def logout():
        user = session.get("user")
        session.clear()
        if user:
            current_app.logger.info(
                "LOGOUT user=%s ip=%s", user, request.remote_addr,
            )
        return redirect(url_for("auth.login"))

    app.register_blueprint(bp)
