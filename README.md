# openredirection

Checks a URL for **open redirection**: a parameter whose value the server uses
as a redirect destination, so an attacker can send a victim to a site they
control through a trusted-looking link.

## How it works

For each candidate redirect parameter the tool sends the canary value
`https://open-redirect-canary.example.invalid/pwned` and does **not** follow the
redirect. A finding is reported when the server answers `301/302/303/307/308`
with a `Location` header that leaves the target's origin.

A change of host or port counts. A change of scheme on the same host does not:
`http -> https` is good practice, not an open redirection.

## Install

```
pip install -r requirements.txt
```

## Usage

```
python openredirection.py -t https://example.com/login
python openredirection.py -t https://example.com/login -p next -p returnUrl
python openredirection.py -t https://example.com/login --timeout 20
```

Exit code is `1` when a finding is reported and `0` when there is none, so the
tool can be used directly in a scan pipeline.

| Flag | Meaning |
| --- | --- |
| `-t`, `--target` | Target URL (http/https required) |
| `-p`, `--param` | Redirect parameter to test, repeatable. Defaults to a common list (`url`, `redirect`, `next`, `returnUrl`, `dest`, ...) |
| `--timeout` | Per-request timeout, default 10s |
| `--dom-check` | Also drive a locally installed Chrome to find client-side redirects |
| `--webdriver-path` | Explicit path to a local ChromeDriver |

## DOM-based redirects

Client-side redirection (`location.href = ...` in JavaScript) is a separate bug
class and is only checked with `--dom-check`. That path needs Selenium and a
locally installed ChromeDriver. Nothing is downloaded or executed at runtime:
`webdriver_manager` was removed from this project for exactly that reason.

## Tests

```
python -m pytest tests -q
```

The tests run a local HTTP fixture server; they need no network access and no
browser.

## Legal disclaimer

For authorized security testing only. You are responsible for having permission
to test the target.