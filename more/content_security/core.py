import base64
import os

from morepath import App
from morepath.request import Request
from more.content_security.policy import ContentSecurityPolicy

# see https://csp.withgoogle.com/docs/faq.html#generating-nonces
NONCE_LENGTH = 16


def random_nonce():
    return base64.b64encode(os.urandom(NONCE_LENGTH)).decode('utf-8')


class ContentSecurityRequest(Request):

    @property
    def content_security_policy(self):
        """ Provides access to a request-local version of the content
        security policy.

        This policy may be modified without having any effect on the default
        security policy.

        """

        if not hasattr(self, '_content_security_policy'):
            self._content_security_policy\
                = self.app.settings.content_security_policy.default.copy()

        return self._content_security_policy

    @content_security_policy.setter
    def content_security_policy(self, policy):
        self._content_security_policy = policy

    def content_security_policy_nonce(self, target):
        """ Generates a nonce that's random once per request, adds it to
        either 'style-src' or 'script-src' and returns its value.

        This can be used to whitelist inline scripts/styles with nonces.

        This way, inline scripts/styles may be used without having to
        allow all of them in one swoop.

        """

        assert target in ('script', 'style')

        policy = self.content_security_policy
        nonce = self.content_security_policy_nonce_value
        directive = '{}_src'.format(target)

        getattr(policy, directive).add("'nonce-{}'".format(nonce))

        return nonce

    @property
    def content_security_policy_nonce_value(self):
        """ Returns the request-bound content security nonce. It is secure
        to keep this once per request. It is only dangerous to use nonces
        over more than one request.

        We use one per request as it ensure that our content security policy
        header doesn't get bloated if there are a lot of inline scripts/styles.

        """

        if not hasattr(self, '_nonce_value'):
            self._nonce_value = random_nonce()

        return self._nonce_value


class ContentSecurityApp(App):
    request_class = ContentSecurityRequest


@ContentSecurityApp.setting('content_security_policy', 'default')
def default_policy():
    return ContentSecurityPolicy()


@ContentSecurityApp.tween_factory()
def content_security_policy_tween_factory(app, handler):

    def content_security_policy_tween(request):
        response = handler(request)

        if hasattr(request, '_content_security_policy'):
            # a custom security policy is used
            policy = request._content_security_policy
        else:
            # the default policy is used
            policy = request.app.settings.content_security_policy.default

        policy.apply(response)

        return response

    return content_security_policy_tween
