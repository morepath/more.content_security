import inspect

from copy import deepcopy

SELF = "'self'"
UNSAFE_INLINE = "'unsafe-inline'"
NONE = "'none'"
STRICT_DYNAMIC = "'strict-dynamic'"


class Directive(object):
    """ Descriptor for the management and rendering of CSP directives.

    Uses types to do some basic sanity checking. This does not ensure
    that the resulting directive is necessarily valid though. For example,
    typos are not caught, nor are non-sensical values.

    Validation is currently out of scope for this project.

    """

    def __init__(self, name, type, default, render):
        self.name = name
        self.type = type
        self.default = default
        self.renderer = render

    def render(self, instance):
        if self.name not in instance.__dict__:
            return None

        if not instance.__dict__[self.name]:
            return None

        return self.renderer(instance.__dict__[self.name])

    def __get__(self, instance, cls):
        if instance is None:
            return self

        if self.name not in instance.__dict__:
            instance.__dict__[self.name] = self.default()

        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        if not isinstance(value, self.type):
            raise TypeError("Expected type {}".format(self.type))

        instance.__dict__[self.name] = value


class SetDirective(Directive):
    def __init__(self, name):
        parent = super(SetDirective, self)
        parent.__init__(name, type=set, default=set, render=render_set)


class SingleValueDirective(Directive):
    def __init__(self, name):
        parent = super(SingleValueDirective, self)
        parent.__init__(name, type=str, default=str, render=str)


class BooleanDirective(Directive):
    def __init__(self, name):
        parent = super(BooleanDirective, self)
        parent.__init__(name, type=bool, default=bool, render=render_bool)


def is_directive(obj):
    return isinstance(obj, Directive)


def render_set(value):
    return ' '.join(sorted(value))


def render_bool(value):
    return '' if value else None


class ContentSecurityPolicy(object):
    """ Defines the complete set of policies available in CSP 1 and 2.

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
    child_src = SetDirective('child-src')
    connect_src = SetDirective('connect-src')
    default_src = SetDirective('default-src')
    font_src = SetDirective('font-src')
    frame_src = SetDirective('frame-src')
    img_src = SetDirective('img-src')
    manifest_src = SetDirective('manifest-src')
    media_src = SetDirective('media-src')
    object_src = SetDirective('object-src')
    script_src = SetDirective('script-src')
    style_src = SetDirective('style-src')
    worker_src = SetDirective('worker-src')

    # Document directives
    base_uri = SetDirective('base-uri')
    plugin_types = SetDirective('plugin-types')
    sandbox = SingleValueDirective('sandbox')
    disown_opener = BooleanDirective('disown-opener')

    # Navigation directives
    form_action = SetDirective('form-action')
    frame_ancestors = SetDirective('frame-ancestors')

    # Reporting directives
    report_uri = SingleValueDirective('report-uri')
    report_to = SingleValueDirective('report-to')

    # Other directives
    block_all_mixed_content = BooleanDirective('block-all-mixed-content')
    require_sri_for = SingleValueDirective('require-sri-for')
    upgrade_insecure_requeists = BooleanDirective('upgrade-insecure-requests')

    def __init__(self, report_only=False, **directives):
        self.report_only = report_only

        for directive in directives:
            name = directive.replace('-', '_')

            assert hasattr(self, name)
            setattr(self, name, directives[directive])

    def copy(self):
        policy = self.__class__()
        policy.__dict__ = deepcopy(self.__dict__)

        return policy

    @property
    def directives(self):
        for name, value in inspect.getmembers(self.__class__, is_directive):
            yield value

    @property
    def text(self):
        values = ((d.name, d.render(self)) for d in self.directives)
        values = ((name, text) for name, text in values if text is not None)

        return ';'.join(' '.join(v).strip() for v in values)

    @property
    def header_name(self):
        if self.report_only:
            return 'Content-Security-Policy-Report-Only'
        else:
            return 'Content-Security-Policy'

    def apply(self, response):
        text = self.text

        if text:
            response.headers[self.header_name] = text
