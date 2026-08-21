import pytest

from enrichment.ioc_normalizer import (
    detect_ioc_type,
    is_valid_domain,
    normalize_ioc,
    normalize_ioc_list,
    normalize_ioc_text,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            " example[.]com ",
            "example.com",
        ),
        (
            "hxxp://example[.]com/path",
            "http://example.com/path",
        ),
        (
            "hxxps://example[.]com/path",
            "https://example.com/path",
        ),
        (
            "https://example.com/path",
            "https://example.com/path",
        ),
    ],
)
def test_normalize_ioc_text(
    value,
    expected,
):
    assert normalize_ioc_text(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        "",
        "   ",
    ],
)
def test_normalize_ioc_text_rejects_invalid_values(
    value,
):
    assert normalize_ioc_text(value) is None


@pytest.mark.parametrize(
    ("value", "expected_type"),
    [
        ("192.0.2.10", "IPv4"),
        ("2001:db8::1", "IPv6"),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            "FileHash-MD5",
        ),
        (
            "a" * 40,
            "FileHash-SHA1",
        ),
        (
            "B" * 64,
            "FileHash-SHA256",
        ),
        (
            "https://example.com/path",
            "URL",
        ),
        (
            "https://192.0.2.10/path",
            "URL",
        ),
        (
            "example.com",
            "domain",
        ),
    ],
)
def test_detect_ioc_type(
    value,
    expected_type,
):
    assert detect_ioc_type(value) == expected_type


@pytest.mark.parametrize(
    "value",
    [
        "not-an-ioc",
        "abcd",
        "http://",
        "https://example.com:invalid/path",
        "ftp://example.com/file",
        "http://invalid_domain/path",
        "",
        None,
    ],
)
def test_detect_ioc_type_rejects_unsupported_values(
    value,
):
    assert detect_ioc_type(value) is None


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "subdomain.example.com",
        "example.co.uk",
        "EXAMPLE.COM",
        "example.com.",
        "a-b.example",
    ],
)
def test_is_valid_domain_accepts_valid_domains(
    domain,
):
    assert is_valid_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "localhost",
        ".example.com",
        "example..com",
        "-example.com",
        "example-.com",
        "example.c",
        "example.123",
        "invalid_domain.com",
        f'{"a" * 64}.example.com',
    ],
)
def test_is_valid_domain_rejects_invalid_domains(
    domain,
):
    assert is_valid_domain(domain) is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "192.168.001.001",
            None,
        ),
        (
            "2001:0db8:0:0:0:0:0:1",
            {
                "indicator": "2001:db8::1",
                "indicator_type": "IPv6",
            },
        ),
        (
            "D41D8CD98F00B204E9800998ECF8427E",
            {
                "indicator": (
                    "d41d8cd98f00b204e9800998ecf8427e"
                ),
                "indicator_type": "FileHash-MD5",
            },
        ),
        (
            "Example.COM.",
            {
                "indicator": "example.com",
                "indicator_type": "domain",
            },
        ),
        (
            "hxxps://example[.]com/path",
            {
                "indicator": "https://example.com/path",
                "indicator_type": "URL",
            },
        ),
    ],
)
def test_normalize_ioc(
    value,
    expected,
):
    assert normalize_ioc(value) == expected


def test_normalize_ioc_list_normalizes_and_deduplicates():
    values = [
        "Example[.]COM",
        "example.com.",
        "192.0.2.10",
        "192.0.2.10",
        "not-an-ioc",
        None,
        "A" * 40,
        "a" * 40,
    ]

    assert normalize_ioc_list(values) == [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "IPv4",
        },
        {
            "indicator": "a" * 40,
            "indicator_type": "FileHash-SHA1",
        },
    ]


@pytest.mark.parametrize(
    "value",
    [
        None,
        "example.com",
        ("example.com",),
        {"indicator": "example.com"},
    ],
)
def test_normalize_ioc_list_requires_a_list(
    value,
):
    with pytest.raises(
        ValueError,
        match="IOC values must be provided as a list",
    ):
        normalize_ioc_list(value)
