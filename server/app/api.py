"""SimpleLogin-compatible HTTP API.

Currently implements the subset needed for Bitwarden's "Forwarded email
alias → SimpleLogin (self-hosted server)" username generator.
"""
from flask import Blueprint, Flask, current_app, jsonify, request

from . import aliases
from .auth import check_credentials
from .config import Config
from .extensions import limiter


bp = Blueprint("api", __name__, url_prefix="/api")

MAX_ATTEMPTS = 20


def _parse_authentication_header(value: str) -> tuple[str, str] | None:
    """Split a SimpleLogin-style `Authentication: user:password` header."""
    if not value or ":" not in value:
        return None
    username, password = value.split(":", 1)
    return username.strip().lower(), password


def _authenticate(config: Config) -> str | None:
    """Return the short username on success, None otherwise.

    Accepts short usernames or full emails (allowlisted domains) in the
    ``Authentication`` header; always returns the short local-part so alias
    targets stay on ``GUISE_DOMAIN``.
    """
    creds = _parse_authentication_header(request.headers.get("Authentication", ""))
    if not creds:
        return None
    raw_username, password = creds
    username, error = check_credentials(raw_username, password, config)
    if username is None:
        current_app.logger.warning(
            "LOGIN_FAILED user=%s ip=%s via=api host=%s:%s err=%s",
            raw_username,
            request.remote_addr,
            config.imap_host,
            config.imap_port,
            error,
        )
        return None
    return username


@bp.route("/alias/random/new", methods=["POST"])
@limiter.limit("30 per minute")
def create_random_alias():
    config: Config = current_app.config["GUISE"]
    username = _authenticate(config)
    if not username:
        return jsonify({"error": "authentication required"}), 401

    target = f"{username}@{config.domain}"

    hostname = (request.args.get("hostname") or "").strip()
    slug = aliases.hostname_to_label(hostname) if config.api_autolabel else ""

    try:
        existing = aliases.list_aliases(config.mailserver_container)
    except RuntimeError as exc:
        current_app.logger.warning("setup alias list failed via api: %s", exc)
        return jsonify({"error": "could not list existing aliases"}), 500

    existing_locals = {a.split("@", 1)[0] for a, _ in existing}

    local_part = None
    for _ in range(MAX_ATTEMPTS):
        candidate = aliases.make_local_part(config.tag, slug)
        if candidate not in existing_locals:
            local_part = candidate
            break
    if local_part is None:
        return jsonify({"error": "could not generate unique alias"}), 500

    alias_addr = f"{local_part}@{config.domain}"
    try:
        aliases.add_alias(config.mailserver_container, alias_addr, target)
    except (RuntimeError, ValueError) as exc:
        current_app.logger.warning(
            "ALIAS_CREATE_FAILED user=%s alias=%s ip=%s via=api err=%s",
            username, alias_addr, request.remote_addr, exc,
        )
        return jsonify({"error": "could not create alias"}), 500

    current_app.logger.info(
        "ALIAS_CREATED user=%s alias=%s ip=%s via=api slug=%s",
        username, alias_addr, request.remote_addr, slug,
    )
    return jsonify({"alias": alias_addr}), 201


def register(app: Flask) -> None:
    app.register_blueprint(bp)
