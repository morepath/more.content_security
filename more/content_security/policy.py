from __future__ import annotations

import inspect

from copy import deepcopy
from typing import TYPE_CHECKING, Any, Generic, TypeGuard, TypeVar, overload

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from typing_extensions import Self

    from webob.response import Response as BaseResponse

_T = TypeVar("_T")

SELF = "'self'"
UNSAFE_INLINE = "'unsafe-inline'"
UNSAFE_EVAL = "'unsafe-eval'"
NONE = "'none'"
STRICT_DYNAMIC = "'strict-dynamic'"


class Directive(Generic[_T]):
    """Descriptor for the management and rendering of CSP directives.

    Uses types to do some basic sanity checking. This does not ensure
    that the resulting directive is necessarily valid though. For example,
    typos are not caught, nor are non-sensical values.

    Validation is currently out of scope for this project.

    """

    def __init__(
        self,
        name: str,
        type: type[_T],
        default: Callable[[], _T],
        render: Callable[[_T], str | None],
    ) -> None:
        self.name = name
        self.type = type
        self.default = default
        self.renderer = render

    def render(self, instance: ContentSecurityPolicy) -> str | None:
        if self.name not in instance.__dict__:
            return None

        if not instance.__dict__[self.name]:
            return None

        return self.renderer(instance.__dict__[self.name])

    @overload
    def __get__(self, instance: None, cls: type[ContentSecurityPolicy]) -> Self: ...
    @overload
    def __get__(
        self, instance: ContentSecurityPolicy, cls: type[ContentSecurityPolicy]
    ) -> _T: ...

    def __get__(
        self, instance: ContentSecurityPolicy | None, cls: type[ContentSecurityPolicy]
    ) -> _T | Self:
        if instance is None:
            return self

        if self.name not in instance.__dict__:
            instance.__dict__[self.name] = self.default()

        return instance.__dict__[self.name]  # type: ignore[no-any-return]

    def __set__(self, instance: ContentSecurityPolicy, value: _T) -> None:
        if not isinstance(value, self.type):
            raise TypeError(f"Expected type {self.type}")

        instance.__dict__[self.name] = value


class SetDirective(Directive[set[str]]):
    def __init__(self, name: str) -> None:
        super().__init__(name, type=set, default=set, render=render_set)


class SingleValueDirective(Directive[str]):
    def __init__(self, name: str) -> None:
        super().__init__(name, type=str, default=str, render=str)


class BooleanDirective(Directive[bool]):
    def __init__(self, name: str) -> None:
        super().__init__(name, type=bool, default=bool, render=render_bool)


def is_directive(obj: object) -> TypeGuard[Directive[Any]]:
    return isinstance(obj, Directive)


def render_set(value: set[str]) -> str:
    return " ".join(sorted(value))


def render_bool(value: bool) -> str | None:
    return "" if value else None


class ContentSecurityPolicy:
    """Defines the complete set of policies available in CSP 1 and 2.

    * Directives which allow for multiple values are defined as sets.
    * Directives which allow for a single value may be set by string.
    * Directives which are boolean in nature are set via True/False.

    The directives are set through properties, with the dashes replaced by
    underscores. For example, 'default-src' becomes 'default_src'.

    Everywhere else (i.e. values) the dashes should be left as they are.

    Example::

        policy = ContentSecurityPolicy()
        policy.default_src.add('http://*.example.com')
        policy.sandbox = "allow-scripts"
        policy.block_all_mixed_content = True

    """

    # Fetch directives
    child_src: SetDirective = SetDirective("child-src")
    connect_src: SetDirective = SetDirective("connect-src")
    default_src: SetDirective = SetDirective("default-src")
    font_src: SetDirective = SetDirective("font-src")
    frame_src: SetDirective = SetDirective("frame-src")
    img_src: SetDirective = SetDirective("img-src")
    manifest_src: SetDirective = SetDirective("manifest-src")
    media_src: SetDirective = SetDirective("media-src")
    object_src: SetDirective = SetDirective("object-src")
    script_src: SetDirective = SetDirective("script-src")
    style_src: SetDirective = SetDirective("style-src")
    worker_src: SetDirective = SetDirective("worker-src")

    # Document directives
    base_uri: SetDirective = SetDirective("base-uri")
    plugin_types: SetDirective = SetDirective("plugin-types")
    sandbox: SingleValueDirective = SingleValueDirective("sandbox")
    disown_opener: BooleanDirective = BooleanDirective("disown-opener")

    # Navigation directives
    form_action: SetDirective = SetDirective("form-action")
    frame_ancestors: SetDirective = SetDirective("frame-ancestors")

    # Reporting directives
    report_uri: SingleValueDirective = SingleValueDirective("report-uri")
    report_to: SingleValueDirective = SingleValueDirective("report-to")

    # Other directives
    block_all_mixed_content: BooleanDirective = BooleanDirective(
        "block-all-mixed-content"
    )
    require_sri_for: SingleValueDirective = SingleValueDirective("require-sri-for")
    upgrade_insecure_requeists: BooleanDirective = BooleanDirective(
        "upgrade-insecure-requests"
    )

    def __init__(
        self,
        report_only: bool = False,
        # NOTE: This is both a little too lax and a little too strict, but
        #       it doesn't seem worth defining a TypedDict, to get better
        #       type checking on this, this will work for most cases and
        #       is not the recommended style of defining the directives
        #       anyways.
        **directives: set[str] | str | bool,
    ) -> None:
        self.report_only = report_only

        for directive in directives:
            name = directive.replace("-", "_")

            assert hasattr(self, name)
            setattr(self, name, directives[directive])

    def copy(self) -> Self:
        policy = self.__class__()
        policy.__dict__ = deepcopy(self.__dict__)

        return policy

    @property
    def directives(self) -> Generator[Directive[Any]]:
        for name, value in inspect.getmembers(self.__class__, is_directive):
            yield value

    @property
    def text(self) -> str:
        values = (
            (d.name, text)
            for d in self.directives
            if (text := d.render(self)) is not None
        )

        return ";".join(" ".join(v).strip() for v in values)

    @property
    def header_name(self) -> str:
        if self.report_only:
            return "Content-Security-Policy-Report-Only"
        else:
            return "Content-Security-Policy"

    def apply(self, response: BaseResponse) -> None:
        text = self.text

        if text:
            response.headers[self.header_name] = text
