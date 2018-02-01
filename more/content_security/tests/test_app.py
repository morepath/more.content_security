import re

from more.content_security import ContentSecurityApp
from more.content_security import ContentSecurityPolicy
from more.content_security import SELF
from webtest import TestApp as Client


def test_content_security_default_remains_untouched():
    class App(ContentSecurityApp):
        pass

    @App.path(path='/')
    class Model(object):
        pass

    @App.view(model=Model)
    def default(self, request):
        return "view"

    @App.view(model=Model, name='protected')
    def protected(self, request):
        request.content_security_policy.default_src.add(SELF)
        return "protected"

    client = Client(App())

    response = client.get('/')
    assert 'Content-Security-Policy' not in response.headers

    response = client.get('/protected')
    assert response.headers['Content-Security-Policy'] == "default-src 'self'"

    response = client.get('/')
    assert 'Content-Security-Policy' not in response.headers


def test_content_security_defaults_may_be_extended():
    class App(ContentSecurityApp):
        pass

    @App.path(path='/')
    class Model(object):
        pass

    @App.view(model=Model)
    def default(self, request):
        return "view"

    @App.view(model=Model, name='extended')
    def protected(self, request):
        request.content_security_policy.default_src.add('https://example.org')
        return "extended"

    @App.setting('content_security_policy', 'default')
    def default_policy():
        return ContentSecurityPolicy(default_src={SELF})

    client = Client(App())

    response = client.get('/')
    assert response.headers['Content-Security-Policy'] == "default-src 'self'"

    response = client.get('/extended')
    assert response.headers['Content-Security-Policy'] == (
        "default-src 'self' https://example.org"
    )


def test_content_security_nonce():
    class App(ContentSecurityApp):
        pass

    @App.path(path='/')
    class Model(object):
        pass

    @App.view(model=Model)
    def default(self, request):
        return '<style nonce="{}"><style><script nonce="{}"></script>'.format(
            request.content_security_policy_nonce('style'),
            request.content_security_policy_nonce('script')
        )

    client = Client(App())

    response = client.get('/')

    text = response.headers['Content-Security-Policy']
    assert "style-src 'nonce-" in text
    assert "script-src 'nonce-" in text

    nonce = re.search(r'nonce-([^\']+)', text).group(1)

    # nonces are per-request, not per nonce call
    assert 'style nonce="{}"'.format(nonce) in response.text
    assert 'script nonce="{}"'.format(nonce) in response.text

    # they're not reused over many requests though!
    response = client.get('/')

    text = response.headers['Content-Security-Policy']
    assert "style-src 'nonce-" in text
    assert "script-src 'nonce-" in text

    assert nonce not in text
    assert nonce != re.search(r'nonce-([^\']+)', text).group(1)


def test_content_security_report_only():
    class App(ContentSecurityApp):
        pass

    @App.path(path='/')
    class Model(object):
        pass

    @App.view(model=Model)
    def default(self, request):
        return "view"

    @App.setting('content_security_policy', 'default')
    def default_policy():
        return ContentSecurityPolicy(report_only=True, default_src={SELF})

    client = Client(App())

    response = client.get('/')
    assert 'Content-Security-Policy' not in response.headers
    assert response.headers['Content-Security-Policy-Report-Only'] == (
        "default-src 'self'"
    )
