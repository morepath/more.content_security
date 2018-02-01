from morepath import App
from morepath.request import Request
from more.content_security import ContentSecurityApp, ContentSecurityPolicy


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


class MyApp(App, ContentSecurityApp):
    request_class = ContentSecurityRequest


@MyApp.setting('content_security_policy', 'default')
def default_policy():
    return ContentSecurityPolicy()


@MyApp.tween_factory()
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
