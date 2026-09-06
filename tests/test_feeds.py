"""KEV and EPSS clients: file:// feeds, empty-feed failures, batching, retries, redirects."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

import trivy_kev_epss as tke
from tests.conftest import EPSS_EMPTY_FEED, KEV_EMPTY_FEED, KEV_FEED, file_url


def test_kev_feed_is_parsed(kev_url: str) -> None:
    catalog = tke.fetch_kev(kev_url)
    assert catalog.count == 3
    assert catalog.catalog_version == "2026.09.04"
    assert catalog.date_released == "2026-09-04T16:47:03.5197Z"
    assert catalog.entries["CVE-2026-48710"] == tke.KevEntry("2026-09-02", "Unknown")
    assert catalog.entries["CVE-2021-44228"].ransomware == "Known"


def test_empty_kev_feed_fails_the_step() -> None:
    with pytest.raises(tke.FeedError, match="no vulnerabilities"):
        tke.fetch_kev(file_url(KEV_EMPTY_FEED))


def test_malformed_kev_feed_fails_the_step(tmp_path: Any) -> None:
    broken = tmp_path / "kev.json"
    broken.write_text("<html>maintenance</html>")
    with pytest.raises(tke.FeedError, match="not valid JSON"):
        tke.fetch_kev(file_url(broken))


def test_epss_file_feed_is_filtered_locally(epss_url: str) -> None:
    scores = tke.fetch_epss(epss_url, ["CVE-2026-48710", "CVE-2020-11023", "GHSA-59g5-xgcq-4qw3"])
    assert set(scores.entries) == {"CVE-2026-48710", "CVE-2020-11023"}
    assert scores.entries["CVE-2026-48710"].score == pytest.approx(0.36257)
    assert scores.entries["CVE-2020-11023"].percentile == pytest.approx(0.99681)
    assert scores.date == "2026-09-05"


def test_cve_absent_from_epss_is_not_a_failure(epss_url: str) -> None:
    scores = tke.fetch_epss(epss_url, ["CVE-2026-48710", "CVE-2026-99999"])
    assert "CVE-2026-99999" not in scores.entries
    assert "CVE-2026-48710" in scores.entries


def test_empty_epss_response_fails_the_step() -> None:
    with pytest.raises(tke.FeedError, match="returned no scores"):
        tke.fetch_epss(file_url(EPSS_EMPTY_FEED), ["CVE-2026-48710"])


def test_epss_is_not_queried_without_cves() -> None:
    scores = tke.fetch_epss("https://unreachable.invalid/epss", ["GHSA-59g5-xgcq-4qw3", "PYSEC-1"])
    assert scores.entries == {}
    assert scores.date is None


def test_epss_status_must_be_ok(tmp_path: Any) -> None:
    broken = tmp_path / "epss.json"
    broken.write_text(json.dumps({"status": "Error", "data": []}))
    with pytest.raises(tke.FeedError, match="status 'Error'"):
        tke.fetch_epss(file_url(broken), ["CVE-2026-48710"])


def test_epss_batches_split_at_100(monkeypatch: pytest.MonkeyPatch) -> None:
    batches: list[list[str]] = []

    def fake_fetch(url: str) -> bytes:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        ids = query["cve"][0].split(",")
        batches.append(ids)
        rows = [{"cve": c, "epss": "0.5", "percentile": "0.9", "date": "2026-09-05"} for c in ids]
        return json.dumps({"status": "OK", "data": rows}).encode()

    monkeypatch.setattr(tke, "fetch_url", fake_fetch)
    ids = [f"CVE-2025-{n:05d}" for n in range(250)]
    scores = tke.fetch_epss("https://api.first.org/data/v1/epss", ids)
    assert [len(b) for b in batches] == [100, 100, 50]
    assert sorted(cve for batch in batches for cve in batch) == sorted(ids)
    assert len(scores.entries) == 250


def test_fetch_url_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[float] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"ok": true}'

    def fake_urlopen(request: Any, timeout: float) -> Response:
        calls.append(timeout)
        if len(calls) < 3:
            raise urllib.error.URLError("connection reset")
        return Response()

    monkeypatch.setattr(tke.urllib.request, "urlopen", fake_urlopen)
    assert tke.fetch_url("https://example.invalid/feed") == b'{"ok": true}'
    assert calls == [30.0, 30.0, 30.0]


def test_fetch_url_gives_up_after_three_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    def fake_urlopen(request: Any, timeout: float) -> Any:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError(request.full_url, 503, "unavailable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(tke.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(tke.FeedError, match="after 3 attempts"):
        tke.fetch_url("https://example.invalid/feed")
    assert attempts == 3


class _FeedHandler(BaseHTTPRequestHandler):
    """A local stand-in for cisa.gov and api.first.org: /kev serves the fixture, /redirect
    301s to /epss, and /epss echoes a score for every queried CVE."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/epss?" + parsed.query)
            self.end_headers()
            return
        if parsed.path == "/epss":
            ids = urllib.parse.parse_qs(parsed.query).get("cve", [""])[0].split(",")
            rows = [
                {"cve": c, "epss": "0.25", "percentile": "0.9", "date": "2026-09-05"}
                for c in ids
                if c
            ]
            body = json.dumps({"status": "OK", "total": len(rows), "data": rows}).encode()
        elif parsed.path == "/kev":
            body = KEV_FEED.read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def feed_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FeedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_http_feeds_follow_redirects_and_carry_the_query(feed_server: str) -> None:
    catalog = tke.fetch_kev(f"{feed_server}/kev")
    assert "CVE-2020-11023" in catalog.entries
    scores = tke.fetch_epss(f"{feed_server}/redirect", ["CVE-2020-11023", "CVE-2026-48710"])
    assert set(scores.entries) == {"CVE-2020-11023", "CVE-2026-48710"}
    assert scores.entries["CVE-2020-11023"].score == pytest.approx(0.25)
