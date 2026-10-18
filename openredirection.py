"""Open redirection checker.

The previous version loaded the target in headless Chrome and compared
`urlparse(driver.current_url).netloc` with `urlparse(target).netloc`. That
cannot detect open redirection: it never supplies a redirect parameter, so
nothing is under the attacker's control. It only reports "the target itself
redirects somewhere else", which is normally legitimate behaviour
(http -> https, apex -> www) and produces constant false positives on sites
that redirect to a marketing or login page.

The check now does what the tool claims to do: it requests the target with a
redirect parameter set to an attacker-controlled canary host, does NOT follow
the redirect, and inspects the Location header. A finding is reported only
when the server answers with a redirect that leaves the target's origin.

DOM-based redirection (JavaScript that rewrites location.href) is a different
bug class and is handled separately behind --dom-check, which requires a
locally installed ChromeDriver. Nothing is downloaded or executed at runtime.
"""

import argparse
import sys
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import requests

# The canary never resolves; if a server redirects here it is handing control
# of the navigation to a third party.
CANARY_HOST = "open-redirect-canary.example.invalid"
CANARY_URL = f"https://{CANARY_HOST}/pwned"

# Common parameter names that carry a redirect target.
DEFAULT_REDIRECT_PARAMS = (
    "url", "redirect", "redirect_url", "redirect_uri", "redirect_url_",
    "next", "return", "returnUrl", "returnTo", "continue", "goto",
    "dest", "destination", "target", "redir", "to", "path", "ref", "view",
)

DEFAULT_TIMEOUT = 10


def netloc_of(url):
    """Return the host:port of a URL, lowercased, for origin comparison."""
    parsed = urlsplit(url)
    return parsed.netloc.lower()


def leaves_origin(location, base_url):
    """True when a Location header sends the browser to a different origin.

    The scheme is deliberately ignored: an http -> https upgrade on the same
    host is good practice, not an open redirection. A change of host or port is.
    Relative Location headers are resolved against base_url first, exactly as a
    browser would.
    """
    if not location:
        return False
    resolved = urljoin(base_url, location.strip())
    return netloc_of(resolved) != netloc_of(base_url)


def set_param(url, name, value):
    """Return url with `name` set to `value`, preserving any existing query."""
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(k, v) for k, v in query if k != name]
    query.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def probe(url, params=DEFAULT_REDIRECT_PARAMS, session=None, timeout=DEFAULT_TIMEOUT):
    """Probe `url` for open redirection.

    Returns a list of dicts, one per parameter the server accepted as a
    redirect target. `session` exists so tests can supply a local fixture.
    """
    session = session or requests.Session()
    findings = []
    for name in params:
        probe_url = set_param(url, name, CANARY_URL)
        try:
            response = session.get(probe_url, allow_redirects=False, timeout=timeout)
        except requests.RequestException as exc:
            print(f"[!] {name}: request failed: {exc}", file=sys.stderr)
            continue

        location = response.headers.get("Location")
        status = response.status_code
        if status in (301, 302, 303, 307, 308) and location:
            if leaves_origin(location, url):
                findings.append({
                    "parameter": name,
                    "status": status,
                    "location": location,
                    "resolved": urljoin(url, location.strip()),
                    "probe_url": probe_url,
                })
    return findings


def check_open_redirection(target, params=DEFAULT_REDIRECT_PARAMS, session=None,
                           timeout=DEFAULT_TIMEOUT):
    """Entry point kept for compatibility. Returns the list of findings."""
    findings = probe(target, params=params, session=session, timeout=timeout)
    for f in findings:
        print(f"[!] Open redirection: parameter '{f['parameter']}' "
              f"returned HTTP {f['status']} -> {f['resolved']}")
    if not findings:
        print(f"[+] No open redirection found at {netloc_of(target)}")
    return findings


def dom_open_redirection(target, driver_path=None):
    """Opt-in check for client-side redirects.

    Requires a locally installed Chrome/ChromeDriver. Selenium 4.x resolves the
    driver itself; nothing is fetched or executed at runtime.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
    except ImportError:
        raise SystemExit(
            "[!] --dom-check needs selenium: pip install selenium\n"
            "    It uses your locally installed ChromeDriver. Nothing is "
            "downloaded or executed at runtime."
        )

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    service = Service(executable_path=driver_path) if driver_path else None
    driver = webdriver.Chrome(service=service, options=options) if service \
        else webdriver.Chrome(options=options)
    try:
        driver.get(target)
        current = driver.current_url
        if netloc_of(current) != netloc_of(target):
            print(f"[!] DOM redirect: {target} -> {current}")
            return True
        print(f"[+] No DOM redirect at {netloc_of(target)}")
        return False
    finally:
        driver.quit()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a target for open redirection vulnerabilities.")
    parser.add_argument("-t", "--target", required=True,
                        help="The target URL, e.g. https://example.com/login")
    parser.add_argument("-p", "--param", action="append", dest="params",
                        help="Redirect parameter to test (repeatable). "
                             "Defaults to a common list.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Per-request timeout in seconds.")
    parser.add_argument("--dom-check", action="store_true",
                        help="Also drive a locally installed Chrome to find "
                             "client-side redirects.")
    parser.add_argument("--webdriver-path",
                        help="Explicit path to a local ChromeDriver.")
    args = parser.parse_args(argv)

    if not args.target.lower().startswith(("http://", "https://")):
        parser.error("--target must be an http:// or https:// URL")

    findings = check_open_redirection(
        args.target,
        params=tuple(args.params) if args.params else DEFAULT_REDIRECT_PARAMS,
        timeout=args.timeout,
    )

    if args.dom_check:
        dom_open_redirection(args.target, driver_path=args.webdriver_path)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())