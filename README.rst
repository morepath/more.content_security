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

To only use the 'ontent-Security-Policy-Report-Only' header, use this:

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

Build Status
------------

.. image:: https://travis-ci.org/morepath/more.content_security.png
  :target: https://travis-ci.org/morepath/more.content_security
  :alt: Build Status

Coverage
--------

.. image:: https://coveralls.io/repos/morepath/more.content_security/badge.png?branch=master
  :target: https://coveralls.io/r/morepath/more.content_security?branch=master
  :alt: Project Coverage

Latest PyPI Release
-------------------

.. image:: https://badge.fury.io/py/more.content_security.svg
    :target: https://badge.fury.io/py/more.content_security
    :alt: Latest PyPI Release

License
-------
more.content_security is released unter the revised BSD license
