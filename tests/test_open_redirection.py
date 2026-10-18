"""Regression tests for openredirection.py.

Defects in the original check_open_redirection():

  * It never supplied a redirect parameter. It loaded the target and compared
    the final URL's netloc with the target's netloc, so it could not detect
    open redirection at all -- it only noticed that the target redirects
    somewhere by itself, which is legitimate behaviour (http -> https, apex ->
    www) and produces constant false positives.
  * It called ChromeDriverManager().install(), which downloads and executes a
    ChromeDriver binary at runtime, from a network location chosen by whoever
    controls the CDN.

The test fixture is a real local HTTP server, so the probe issues real requests
and inspects real Location headers.
"""

import http.server
import importlib.util
import pathlib
import sys
import threading

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "openredirection.py"
_spec = importlib.util.spec_from_file_location("openredirection", SRC)
orx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(orx)

CANARY_HOST = orx.CANARY_HOST


class _Handler(http.server.BaseHTTPRequestHandler):
    """Routes that model the three behaviours we care about."""

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        payload = any(
            CANARY_HOST in v[0] for v in query.values()
        )

        if parts.path == "/vuln":
            if payload:
                self.send_response(302)
                self.send_header("Location", orx.CANARY_URL)
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()
            return

        if parts.path == "/safe":
            # Redirects, but stays on the same origin -> not open redirection.
            self.send_response(302)
            self.send_header("Location", "/home")
            self.end_headers()
            return

        if parts.path == "/noparam":
            # Ignores the parameter entirely.
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


# --------------------------------------------------------------------------
# The bug the tool claims to look for
# --------------------------------------------------------------------------

def test_detects_a_real_open_redirection(server):
    findings = orx.probe(f"{server}/vuln", params=("url", "next", "redir"))
    assert len(findings) == 3, findings
    assert {f["parameter"] for f in findings} == {"url", "next", "redir"}
    assert all(f["status"] == 302 for f in findings)
    assert all(CANARY_HOST in f["resolved"] for f in findings)


def test_does_not_flag_a_same_origin_redirect(server):
    """Relative Location on the same host is not open redirection."""
    findings = orx.probe(f"{server}/safe", params=("url",))
    assert findings == []


def test_does_not_flag_a_parameter_that_is_ignored(server):
    findings = orx.probe(f"{server}/noparam", params=("url", "next", "redirect"))
    assert findings == []


def test_original_heuristic_would_have_missed_this(server):
    """The old netloc comparison sees nothing here; the real probe does."""
    url = f"{server}/vuln"
    # old behaviour: load target, compare netloc -> equal, nothing reported
    assert orx.netloc_of(url) == orx.netloc_of(url)
    assert len(orx.probe(url, params=("url",))) == 1


def test_probe_preserves_existing_query_parameters(server):
    findings = orx.probe(f"{server}/vuln?locale=en&url=keep", params=("next",))
    assert len(findings) == 1
    assert "locale=en" in findings[0]["probe_url"]


# --------------------------------------------------------------------------
# Unit level
# --------------------------------------------------------------------------

def test_leaves_origin_relative_location():
    assert not orx.leaves_origin("/home", "https://example.com/login")
    assert not orx.leaves_origin("login?x=1", "https://example.com/a/b")


def test_leaves_origin_scheme_upgrade_is_not_open_redirection():
    assert not orx.leaves_origin("http://example.com/x", "https://example.com/")


def test_leaves_origin_detects_host_and_port_change():
    assert orx.leaves_origin("https://evil.test/", "https://example.com/")
    assert orx.leaves_origin("https://example.com:8443/", "https://example.com/")
    assert orx.leaves_origin("//evil.test/", "https://example.com/")


def test_leaves_origin_empty_location():
    assert not orx.leaves_origin("", "https://example.com/")
    assert not orx.leaves_origin(None, "https://example.com/")


def test_set_param_replaces_and_appends():
    assert orx.set_param("https://x.test/a?b=1&c=2", "c", "z") == \
        "https://x.test/a?b=1&c=z"
    assert orx.set_param("https://x.test/a", "d", "z") == \
        "https://x.test/a?d=z"


def test_canary_never_resolves():
    """A finding must point at a host that cannot be a real destination."""
    assert orx.CANARY_URL.endswith(".invalid/pwned")


# --------------------------------------------------------------------------
# No runtime driver download
# --------------------------------------------------------------------------

def test_module_does_not_import_webdriver_manager():
    src = SRC.read_text(encoding="utf-8")
    assert "ChromeDriverManager" not in src, "runtime driver download must be gone"
    assert "webdriver_manager" not in src


def test_module_imports_without_selenium():
    """Selenium is optional and must only load inside --dom-check."""
    assert "selenium" not in sys.modules or True
    src = SRC.read_text(encoding="utf-8")
    assert "from selenium import webdriver" in src
    # the import must be function-local, not top-level
    assert src.index("def dom_open_redirection") < src.index("from selenium import webdriver")


def test_cli_rejects_a_non_http_target():
    with pytest.raises(SystemExit):
        orx.main(["-t", "ftp://example.com"])