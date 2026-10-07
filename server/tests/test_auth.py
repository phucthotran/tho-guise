from unittest.mock import MagicMock, patch

import pytest

from app import auth
from app.config import Config


@pytest.fixture
def config(tmp_path):
    return Config(
        domain="example.com",
        allowed_domains=frozenset({"example.com"}),
        tag="g-",
        denied_users=frozenset({"gitea", "immich"}),
        mailserver_container="mailserver",
        imap_host="mailserver",
        imap_port=993,
        imap_timeout=30.0,
        imap_cafile=None,
        imap_insecure=False,
        api_autolabel=True,
        data_dir=tmp_path,
        secret_key="test-secret",
        session_cookie_secure=False,
    )


@pytest.fixture
def multi_domain_config(tmp_path):
    return Config(
        domain="example.com",
        allowed_domains=frozenset({"example.com", "other.com"}),
        tag="g-",
        denied_users=frozenset(),
        mailserver_container="mailserver",
        imap_host="mailserver",
        imap_port=993,
        imap_timeout=30.0,
        imap_cafile=None,
        imap_insecure=False,
        api_autolabel=True,
        data_dir=tmp_path,
        secret_key="test-secret",
        session_cookie_secure=False,
    )


class TestImapCheck:
    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_success(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        result = auth._imap_check("alice@example.com", "password", config)
        assert result.ok is True
        assert result.error is None
        instance.login.assert_called_once_with("alice@example.com", "password")

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_bad_password(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        instance.login.side_effect = auth.imaplib.IMAP4.error("LOGIN failed")
        mock_imap.return_value = instance
        result = auth._imap_check("alice@example.com", "bad", config)
        assert result.ok is False
        assert result.error is not None
        # imaplib.IMAP4.error reports type name as plain "error"
        assert "LOGIN failed" in result.error
        assert "host=mailserver:993" in result.error
        assert "bad" not in result.error  # password must never appear

    @patch("app.auth.imaplib.IMAP4_SSL", side_effect=OSError("connection refused"))
    def test_network_error(self, mock_imap, config):
        result = auth._imap_check("alice@example.com", "p", config)
        assert result.ok is False
        assert "OSError" in (result.error or "")
        assert "connection refused" in (result.error or "")

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_hostname_check_disabled(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        auth._imap_check("alice@example.com", "p", config)
        _, kwargs = mock_imap.call_args
        ctx = kwargs["ssl_context"]
        assert ctx.check_hostname is False

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_uses_configured_timeout(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        auth._imap_check("alice@example.com", "p", config)
        _, kwargs = mock_imap.call_args
        assert kwargs["timeout"] == 30.0

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_cert_verification_required_by_default(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        auth._imap_check("alice@example.com", "p", config)
        _, kwargs = mock_imap.call_args
        ctx = kwargs["ssl_context"]
        import ssl as _ssl
        assert ctx.verify_mode == _ssl.CERT_REQUIRED

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_insecure_mode_disables_verification(self, mock_imap, tmp_path):
        insecure_config = Config(
            domain="example.com",
            allowed_domains=frozenset({"example.com"}),
            tag="g-", denied_users=frozenset(),
            mailserver_container="mailserver", imap_host="mailserver",
            imap_port=993, imap_timeout=30.0, imap_cafile=None, imap_insecure=True,
            api_autolabel=True, data_dir=tmp_path, secret_key="test",
            session_cookie_secure=False,
        )
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        auth._imap_check("alice@example.com", "p", insecure_config)
        _, kwargs = mock_imap.call_args
        ctx = kwargs["ssl_context"]
        import ssl as _ssl
        assert ctx.verify_mode == _ssl.CERT_NONE


class TestImapErrorDetail:
    def test_includes_type_host_port(self, config):
        detail = auth._imap_error_detail(OSError("Name or service not known"), config)
        assert detail.startswith("OSError:")
        assert "Name or service not known" in detail
        assert "host=mailserver:993" in detail

    def test_collapses_whitespace_and_truncates(self, config):
        long = "x" * 300
        detail = auth._imap_error_detail(RuntimeError(f"line1\n{long}"), config)
        assert "\n" not in detail
        assert "..." in detail
        assert detail.endswith("host=mailserver:993")
        assert len(detail) < 220


class TestNormalizeLoginUsername:
    def test_short_username(self, config):
        identity = auth.normalize_login_username("alice", config)
        assert isinstance(identity, auth.LoginIdentity)
        assert identity.username == "alice"
        assert identity.imap_username == "alice@example.com"

    def test_full_email_primary_domain(self, config):
        identity = auth.normalize_login_username("alice@example.com", config)
        assert isinstance(identity, auth.LoginIdentity)
        assert identity.username == "alice"
        assert identity.imap_username == "alice@example.com"

    def test_domain_case_insensitive(self, config):
        identity = auth.normalize_login_username("alice@EXAMPLE.COM", config)
        assert isinstance(identity, auth.LoginIdentity)
        assert identity.username == "alice"
        assert identity.imap_username == "alice@example.com"

    def test_unknown_domain_rejected(self, config):
        err = auth.normalize_login_username("alice@other.com", config)
        assert isinstance(err, auth.NormalizeError)
        assert err.reason == "unknown_domain"
        assert "Permitted domains:" in err.message
        assert "example.com" in err.message

    def test_allowlisted_alternate_domain(self, multi_domain_config):
        identity = auth.normalize_login_username("alice@other.com", multi_domain_config)
        assert isinstance(identity, auth.LoginIdentity)
        assert identity.username == "alice"
        assert identity.imap_username == "alice@other.com"

    def test_empty_rejected(self, config):
        err = auth.normalize_login_username("", config)
        assert isinstance(err, auth.NormalizeError)
        assert err.reason == "empty"

    def test_bad_local_part(self, config):
        err = auth.normalize_login_username("Alice", config)
        assert isinstance(err, auth.NormalizeError)
        assert err.reason == "bad_username"

    def test_empty_local_with_matching_domain(self, config):
        err = auth.normalize_login_username("@example.com", config)
        assert isinstance(err, auth.NormalizeError)
        assert err.reason == "bad_username"

    def test_multiple_at_signs_domain_not_allowed(self, config):
        # First @ is the separator; domain becomes "example@example.com"
        err = auth.normalize_login_username("alice@example@example.com", config)
        assert isinstance(err, auth.NormalizeError)
        assert err.reason == "unknown_domain"


class TestBuildImapUsername:
    def test_appends_guise_domain(self, config):
        assert auth.build_imap_username("alice", config) == "alice@example.com"


class TestVerifyCredentials:
    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_short_username(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        assert auth.verify_credentials("alice", "pw", config) == "alice"
        instance.login.assert_called_once_with("alice@example.com", "pw")

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_full_email_primary_domain(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        assert auth.verify_credentials("alice@example.com", "pw", config) == "alice"
        instance.login.assert_called_once_with("alice@example.com", "pw")

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_allowlisted_alternate_domain(self, mock_imap, multi_domain_config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        assert auth.verify_credentials("alice@other.com", "pw", multi_domain_config) == "alice"
        instance.login.assert_called_once_with("alice@other.com", "pw")

    def test_unknown_domain(self, config):
        assert auth.verify_credentials("alice@evil.com", "pw", config) is None

    def test_denied_user(self, config):
        assert auth.verify_credentials("gitea", "pw", config) is None

    def test_empty_password(self, config):
        assert auth.verify_credentials("alice", "", config) is None

    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_bad_password(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        instance.login.side_effect = auth.imaplib.IMAP4.error("LOGIN failed")
        mock_imap.return_value = instance
        assert auth.verify_credentials("alice", "bad", config) is None


class TestCheckCredentials:
    @patch("app.auth.imaplib.IMAP4_SSL")
    def test_success(self, mock_imap, config):
        instance = MagicMock()
        instance.__enter__.return_value = instance
        mock_imap.return_value = instance
        user, err = auth.check_credentials("alice", "pw", config)
        assert user == "alice"
        assert err is None

    @patch("app.auth.imaplib.IMAP4_SSL", side_effect=OSError("Name or service not known"))
    def test_returns_log_safe_imap_error(self, mock_imap, config):
        user, err = auth.check_credentials("alice", "secret-password", config)
        assert user is None
        assert err is not None
        assert "OSError" in err
        assert "host=mailserver:993" in err
        assert "secret-password" not in err

    def test_normalize_error(self, config):
        user, err = auth.check_credentials("alice@evil.com", "pw", config)
        assert user is None
        assert err == "normalize:unknown_domain"


class TestSafeNextUrl:
    DEFAULT = "/"

    def test_empty_returns_default(self):
        assert auth._safe_next_url("", self.DEFAULT) == self.DEFAULT
        assert auth._safe_next_url(None, self.DEFAULT) == self.DEFAULT

    def test_simple_path_preserved(self):
        assert auth._safe_next_url("/dashboard", self.DEFAULT) == "/dashboard"

    def test_path_with_query_preserved(self):
        assert auth._safe_next_url("/foo?x=1&y=2", self.DEFAULT) == "/foo?x=1&y=2"

    def test_root_preserved(self):
        assert auth._safe_next_url("/", self.DEFAULT) == "/"

    def test_protocol_relative_rejected(self):
        assert auth._safe_next_url("//evil.com/path", self.DEFAULT) == self.DEFAULT
        assert auth._safe_next_url("//evil.com", self.DEFAULT) == self.DEFAULT

    def test_backslash_smuggle_rejected(self):
        assert auth._safe_next_url("/\\evil.com", self.DEFAULT) == self.DEFAULT

    def test_absolute_url_rejected(self):
        assert auth._safe_next_url("https://evil.com/", self.DEFAULT) == self.DEFAULT
        assert auth._safe_next_url("http://evil.com/", self.DEFAULT) == self.DEFAULT

    def test_scheme_relative_rejected(self):
        # Some browsers / proxies treat these oddly
        assert auth._safe_next_url("javascript:alert(1)", self.DEFAULT) == self.DEFAULT

    def test_relative_path_rejected(self):
        # Must start with single '/' — anything else (including relative) defaults
        assert auth._safe_next_url("foo", self.DEFAULT) == self.DEFAULT


class TestCsrfValid:
    def test_match(self):
        assert auth._csrf_valid("abc123", "abc123") is True

    def test_mismatch(self):
        assert auth._csrf_valid("abc123", "xyz456") is False

    def test_empty_submitted(self):
        assert auth._csrf_valid("", "abc123") is False
        assert auth._csrf_valid(None, "abc123") is False

    def test_empty_expected(self):
        assert auth._csrf_valid("abc123", "") is False
        assert auth._csrf_valid("abc123", None) is False

    def test_both_empty(self):
        assert auth._csrf_valid("", "") is False
        assert auth._csrf_valid(None, None) is False


class TestUsernameRegex:
    def test_accepts_simple(self):
        assert auth.USERNAME_RE.match("alice")

    def test_accepts_dot_username(self):
        assert auth.USERNAME_RE.match("first.last")

    def test_rejects_at(self):
        assert not auth.USERNAME_RE.match("user@example.com")

    def test_rejects_uppercase(self):
        assert not auth.USERNAME_RE.match("Alice")

    def test_rejects_empty(self):
        assert not auth.USERNAME_RE.match("")
