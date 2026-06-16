from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING, Literal

from morepath import App
from morepath.request import Request
from more.content_security.policy import ContentSecurityPolicy

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing_extensions import TypeVar

    from webob import Response as BaseResponse

    from morepath.types import Tween

    _AppT = TypeVar(
        "_AppT",
        bound="ContentSecurityApp",
        default="ContentSecurityApp",
        covariant=True,
    )
else:
    from typing import TypeVar

    _AppT = TypeVar("_AppT", bound="ContentSecurityApp", covariant=True)

# see https://csp.withgoogle.com/docs/faq.html#generating-nonces
NONCE_LENGTH = 16


def random_nonce() -> str:
    return base64.b64encode(os.urandom(NONCE_LENGTH)).decode("utf-8")


class ContentSecurityRequest(Request[_AppT]):
    @property
    def content_security_policy(self) -> ContentSecurityPolicy:
        """Provides access to a request-local version of the content
        security policy.

        This policy may be modified without having any effect on the default
        security policy.

        """

        if not hasattr(self, "_content_security_policy"):
            self._content_security_policy = (
                self.app.settings.content_security_policy.default.copy()
            )

        return self._content_security_policy  # type: ignore[no-any-return]

    @content_security_policy.setter
    def content_security_policy(self, policy: ContentSecurityPolicy) -> None:
        self._content_security_policy = policy

    def content_security_policy_nonce(self, target: Literal["script", "style"]) -> str:
        """Generates a nonce that's random once per request, adds it to
        either 'style-src' or 'script-src' and returns its value.

        This can be used to whitelist inline scripts/styles with nonces.

        This way, inline scripts/styles may be used without having to
        allow all of them in one swoop.

        """

        assert target in ("script", "style")

        policy = self.content_security_policy
        nonce = self.content_security_policy_nonce_value
        directive = f"{target}_src"

        getattr(policy, directive).add(f"'nonce-{nonce}'")

        return nonce

    @property
    def content_security_policy_nonce_value(self) -> str:
        """Returns the request-bound content security nonce. It is secure
        to keep this once per request. It is only dangerous to use nonces
        over more than one request.

        We use one per request as it ensure that our content security policy
        header doesn't get bloated if there are a lot of inline scripts/styles.

        """

        if not hasattr(self, "_nonce_value"):
            self._nonce_value = random_nonce()

        return self._nonce_value


class ContentSecurityApp(App):
    request_class = ContentSecurityRequest


@ContentSecurityApp.setting("content_security_policy", "default")
def default_policy() -> ContentSecurityPolicy:
    return ContentSecurityPolicy()


@ContentSecurityApp.setting("content_security_policy", "apply_policy")
def default_policy_apply_factory() -> (
    Callable[[ContentSecurityPolicy, Request, BaseResponse], None]
):
    def apply_policy(
        policy: ContentSecurityPolicy, request: Request, response: BaseResponse
    ) -> None:
        policy.apply(response)

    return apply_policy


@ContentSecurityApp.tween_factory()
def content_security_policy_tween_factory(
    app: ContentSecurityApp, handler: Tween
) -> Tween:
    policy_settings = app.settings.content_security_policy

    def content_security_policy_tween(request: ContentSecurityRequest) -> BaseResponse:
        response = handler(request)

        if hasattr(request, "_content_security_policy"):
            # a custom security policy is used
            policy = request._content_security_policy
        else:
            # the default policy is used
            policy = policy_settings.default

        policy_settings.apply_policy(policy, request, response)

        return response

    return content_security_policy_tween
