from app.config import _parse_allowed_domains, load_config


class TestParseAllowedDomains:
    def test_default_is_guise_domain_only(self, monkeypatch):
        monkeypatch.delenv("GUISE_ALLOWED_DOMAINS", raising=False)
        assert _parse_allowed_domains("example.com") == frozenset({"example.com"})

    def test_extra_domains_union_with_primary(self, monkeypatch):
        monkeypatch.setenv("GUISE_ALLOWED_DOMAINS", "other.com, Third.COM")
        assert _parse_allowed_domains("example.com") == frozenset(
            {"example.com", "other.com", "third.com"}
        )

    def test_empty_entries_ignored(self, monkeypatch):
        monkeypatch.setenv("GUISE_ALLOWED_DOMAINS", ", other.com , ")
        assert _parse_allowed_domains("example.com") == frozenset(
            {"example.com", "other.com"}
        )


class TestLoadConfig:
    def test_allowed_domains_loaded(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GUISE_DOMAIN", "example.com")
        monkeypatch.setenv("GUISE_ALLOWED_DOMAINS", "mail.example.com")
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
        cfg = load_config()
        assert cfg.domain == "example.com"
        assert cfg.allowed_domains == frozenset({"example.com", "mail.example.com"})

    def test_imap_timeout_default_and_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GUISE_DOMAIN", "example.com")
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("SESSION_COOKIE_SECURE", "0")
        monkeypatch.delenv("GUISE_IMAP_TIMEOUT", raising=False)
        assert load_config().imap_timeout == 30.0
        monkeypatch.setenv("GUISE_IMAP_TIMEOUT", "45")
        assert load_config().imap_timeout == 45.0
