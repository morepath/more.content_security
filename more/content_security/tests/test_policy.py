import pytest

from more.content_security import ContentSecurityPolicy


def test_policy_initialisation():
    policy = ContentSecurityPolicy(default_src={"https://example.org"})
    assert policy.text == "default-src https://example.org"

    policy = ContentSecurityPolicy(**{'default-src': {"https://example.org"}})
    assert policy.text == "default-src https://example.org"


def test_multivalue_directive():
    policy = ContentSecurityPolicy()
    assert policy.text == ""

    policy.default_src.add("https://example.org")
    assert policy.text == "default-src https://example.org"

    policy.default_src.add("https://foobar.org")
    assert policy.text == "default-src https://example.org https://foobar.org"

    policy.default_src.clear()
    assert policy.text == ""

    policy.default_src = set()
    assert policy.text == ""

    with pytest.raises(TypeError):
        policy.default_src = []


def test_singevalue_directive():
    policy = ContentSecurityPolicy()

    policy.sandbox = "allow-forms"
    assert policy.text == "sandbox allow-forms"

    policy.sandbox = ""
    assert policy.text == ""

    with pytest.raises(TypeError):
        policy.sandbox = None


def test_boolean_directive():
    policy = ContentSecurityPolicy()

    policy.block_all_mixed_content = True
    assert policy.text == "block-all-mixed-content"

    policy.block_all_mixed_content = False
    assert policy.text == ""

    with pytest.raises(TypeError):
        policy.block_all_mixed_content = None


def test_multiple_directives():
    policy = ContentSecurityPolicy()

    policy.default_src.add("https://example.org")
    policy.default_src.add("https://foobar.org")
    policy.sandbox = "allow-forms"
    policy.block_all_mixed_content = True

    assert policy.text == (
        "block-all-mixed-content;"
        "default-src https://example.org https://foobar.org;"
        "sandbox allow-forms"
    )


def test_copy_directive():
    policy = ContentSecurityPolicy()
    assert policy.text == ""

    policy.default_src.add("https://example.org")
    assert policy.text == "default-src https://example.org"

    copied = policy.copy()
    assert copied.text == "default-src https://example.org"

    copied.default_src.clear()
    assert copied.text == ""
    assert policy.text == "default-src https://example.org"
