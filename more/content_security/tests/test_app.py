from __future__ import annotations

import re
from typing import TYPE_CHECKING

from more.content_security import ContentSecurityApp
from more.content_security import ContentSecurityPolicy
from more.content_security import SELF
from webtest import TestApp as Client

if TYPE_CHECKING:
    from more.content_security.core import ContentSecurityRequest


def test_content_security_default_remains_untouched() -> None:
    class App(ContentSecurityApp):
        pass

    @App.path(path="/")
    class Model:
        pass

    @App.view(model=Model)
    def default(self: Model, request: ContentSecurityRequest) -> str:
        return "view"

    @App.view(model=Model, name="protected")
    def protected(self: Model, request: ContentSecurityRequest) -> str:
        request.content_security_policy.default_src.add(SELF)
        return "protected"

    client = Client(App())

    response = client.get("/")
    assert "Content-Security-Policy" not in response.headers

    response = client.get("/protected")
    assert response.headers["Content-Security-Policy"] == "default-src 'self'"

    response = client.get("/")
    assert "Content-Security-Policy" not in response.headers


def test_content_security_defaults_may_be_extended() -> None:
    class App(ContentSecurityApp):
        pass

    @App.path(path="/")
    class Model:
        pass

    @App.view(model=Model)
    def default(self: Model, request: ContentSecurityRequest) -> str:
        return "view"

    @App.view(model=Model, name="extended")
    def protected(self: Model, request: ContentSecurityRequest) -> str:
        request.content_security_policy.default_src.add("https://example.org")
        return "extended"

    @App.setting("content_security_policy", "default")
    def default_policy() -> ContentSecurityPolicy:
        return ContentSecurityPolicy(default_src={SELF})

    client = Client(App())

    response = client.get("/")
    assert response.headers["Content-Security-Policy"] == "default-src 'self'"

    response = client.get("/extended")
    assert response.headers["Content-Security-Policy"] == (
        "default-src 'self' https://example.org"
    )


def test_content_security_nonce() -> None:
    class App(ContentSecurityApp):
        pass

    @App.path(path="/")
    class Model:
        pass

    @App.view(model=Model)
    def default(self: Model, request: ContentSecurityRequest) -> str:
        return '<style nonce="{}"><style><script nonce="{}"></script>'.format(
            request.content_security_policy_nonce("style"),
            request.content_security_policy_nonce("script"),
        )

    client = Client(App())

    response = client.get("/")

    text = response.headers["Content-Security-Policy"]
    assert "style-src 'nonce-" in text
    assert "script-src 'nonce-" in text

    match = re.search(r"nonce-([^\']+)", text)
    assert match is not None
    nonce = match.group(1)

    # nonces are per-request, not per nonce call
    assert f'style nonce="{nonce}"' in response.text
    assert f'script nonce="{nonce}"' in response.text

    # they're not reused over many requests though!
    response = client.get("/")

    text = response.headers["Content-Security-Policy"]
    assert "style-src 'nonce-" in text
    assert "script-src 'nonce-" in text

    assert nonce not in text
    match = re.search(r"nonce-([^\']+)", text)
    assert match is not None
    assert nonce != match.group(1)


def test_content_security_report_only() -> None:
    class App(ContentSecurityApp):
        pass

    @App.path(path="/")
    class Model:
        pass

    @App.view(model=Model)
    def default(self: Model, request: ContentSecurityRequest) -> str:
        return "view"

    @App.setting("content_security_policy", "default")
    def default_policy() -> ContentSecurityPolicy:
        return ContentSecurityPolicy(report_only=True, default_src={SELF})

    client = Client(App())

    response = client.get("/")
    assert "Content-Security-Policy" not in response.headers
    assert response.headers["Content-Security-Policy-Report-Only"] == (
        "default-src 'self'"
    )
