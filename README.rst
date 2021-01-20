.. image:: https://github.com/morepath/more.content_security/workflows/CI/badge.svg?branch=master
   :target: https://github.com/morepath/more.content_security/actions?workflow=CI
   :alt: CI Status

.. image:: https://coveralls.io/repos/github/morepath/more.content_security/badge.svg?branch=master
    :target: https://coveralls.io/github/morepath/more.content_security?branch=master

.. image:: https://img.shields.io/pypi/v/more.content_security.svg
  :target: https://pypi.org/project/more.content_security/

.. image:: https://img.shields.io/pypi/pyversions/more.content_security.svg
  :target: https://pypi.org/project/more.content_security/



more.content_security
=====================

Content Security Policy for Morepath

Usage
-----

To protect all views with a default content security policy:

.. code-block:: python

    from morepath import App
    from more.content_security import ContentSecurityApp
    from more.content_security import ContentSecurityPolicy
    from more.content_security import SELF

    class MyApp(App, ContentSecurityApp):
        pass

    @MyApp.setting('content_security_policy', 'default')
    def default_policy():
        return ContentSecurityPolicy(
            default_src={SELF},
            script_src={SELF, 'https://analytics.example.org'}
        )

To extend the default policy for the default view of a model:

.. code-block:: python

    @MyApp.view(model=Document)
    def view_document(self, request):

        # the actual default policy is not modified here!
        request.content_security_policy.script_src.add('https://cdnjs.com')

        ....

We can also use a completely different policy:

.. code-block:: python

    @MyApp.view(model=Document)
    def view_document(self, request):
        request.content_security_policy = ContentSecurityPolicy()

Additionally, we can use nonces in inline scripty/stylesheets. Those will
automatically be added to the 'script-src', 'style-src' directives:

.. code-block:: python

    @MyApp.html(model=Document)
    def view_document(self, request):
        return """
            <html>
                ...

                <script nonce="{}">...</script>
            </html>
        """.format(request.content_security_policy_nonce('script'))

Note that we use a custom request class for nonces. If you have your own,
you need to extend it as follows:

.. code-block:: python

    from morepath.request import Request
    from more.content_security import ContentSecurityRequest

    class CustomRequest(Request, ContentSecurityRequest):
        pass

    class MyApp(App, ContentSecurityApp):
        request_class = CustomRequest

To only use the 'Content-Security-Policy-Report-Only' header, use this:

.. code-block:: python

    @MyApp.setting('content_security_policy', 'default')
    def default_policy():
        return ContentSecurityPolicy(
            report_only=True,
            default_src={SELF}
        )

Run the Tests
-------------

Install tox and run it::

    pip install tox
    tox

Limit the tests to a specific python version::

    tox -e py27

Conventions
-----------

more.content_security follows PEP8 as close as possible. To test for it run::

    tox -e pep8

more.content_security uses `Semantic Versioning <http://semver.org/>`_

License
-------
more.content_security is released unter the revised BSD license
