import ursa_minor.engagement as engagement


def _isolate_engagements(monkeypatch, tmp_path):
    engagement_dir = tmp_path / "engagements"
    monkeypatch.setattr(engagement, "_ENG_DIR", engagement_dir)
    monkeypatch.setattr(engagement, "_ACTIVE_FILE", engagement_dir / ".active")


def test_scope_fails_closed_without_active_engagement(monkeypatch, tmp_path):
    _isolate_engagements(monkeypatch, tmp_path)

    result = engagement.check("10.0.0.5")

    assert result["in_scope"] is False
    assert result["allow_destructive"] is False
    assert "No active engagement" in result["reason"]


def test_scope_accepts_urls_hosts_and_subnets(monkeypatch, tmp_path):
    _isolate_engagements(monkeypatch, tmp_path)
    engagement.create(
        name="Authorized lab",
        scope_hosts="10.0.0.0/24,app.example.test",
        scope_paths="/api,/health",
    )

    assert engagement.check("10.0.0.5")["in_scope"] is True
    assert engagement.check("10.0.0.0/28")["in_scope"] is True
    assert engagement.check("app.example.test:8443")["in_scope"] is True
    assert engagement.check("https://app.example.test/api/v1")["in_scope"] is True
    assert engagement.check("https://app.example.test/api-evil")["in_scope"] is False


def test_scope_rejects_network_that_exceeds_authorized_cidr(monkeypatch, tmp_path):
    _isolate_engagements(monkeypatch, tmp_path)
    engagement.create(name="Small lab", scope_hosts="10.0.0.0/28")

    result = engagement.check("10.0.0.0/24")

    assert result["in_scope"] is False
    assert "not in scope" in result["reason"]


def test_engagement_requires_at_least_one_scope_target(monkeypatch, tmp_path):
    _isolate_engagements(monkeypatch, tmp_path)

    try:
        engagement.create(name="Invalid", scope_hosts="")
    except ValueError as exc:
        assert "scope_hosts" in str(exc)
    else:
        raise AssertionError("empty engagement scope was accepted")
