import pytest

from security.cors_policy import (
    allow_origin,
    allow_credentials,
    preflight,
    vary_header,
    is_null_origin,
    max_age_ok
)


def test_exact():
    assert allow_origin('https://app.example', {'https://app.example'}) == 'https://app.example'

def test_wildcard_cred():
    assert allow_credentials('*', True) is False

def test_null():
    assert is_null_origin('null') is True

def test_null_reject():
    assert allow_origin('null', {'https://app.example'}) is None

def test_subdomain():
    assert allow_origin('https://sub.app.example', {'https://app.example'}) is None

def test_preflight():
    assert preflight('POST', ['content-type'], {'POST'}, {'content-type'}) is True

def test_bad_method():
    assert preflight('DELETE', [], {'POST'}, set()) is False

def test_bad_header():
    assert preflight('POST', ['x-evil'], {'POST'}, {'content-type'}) is False

def test_max_age():
    assert max_age_ok(600) is False

def test_vary():
    assert vary_header('https://app.example') == 'Origin'

def test_no_cors():
    assert allow_origin('https://evil', {'https://app.example'}) is None

def test_private():
    assert preflight('GET', ['access-control-request-private-network'], {'GET'}, set()) is False

def test_credentials():
    assert allow_credentials('https://app.example', True) is True

def test_empty():
    assert allow_origin('', {'https://app.example'}) is None

def test_case():
    assert allow_origin('https://APP.example', {'https://app.example'}) is None
