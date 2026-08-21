import pytest

from enrichment.cve_enricher import (
    get_preffered_cvss_matrics,
    get_preffered_description,
    get_reference_links,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "descriptions",
    [
        None,
        {},
        "English description",
    ],
)
def test_description_requires_list(
    descriptions,
):
    assert get_preffered_description(
        descriptions
    ) == ""


def test_description_prefers_english():
    descriptions = [
        None,
        {
            "lang": "fr",
            "value": "Description française",
        },
        {
            "lang": "en",
            "value": "English description",
        },
        {
            "lang": "de",
            "value": "Deutsche Beschreibung",
        },
    ]

    assert get_preffered_description(
        descriptions
    ) == "English description"


def test_description_falls_back_to_french():
    descriptions = [
        {
            "lang": "en",
            "value": "",
        },
        {
            "lang": "fr",
            "value": "Description française",
        },
        {
            "lang": "de",
            "value": "Deutsche Beschreibung",
        },
    ]

    assert get_preffered_description(
        descriptions
    ) == "Description française"


def test_description_falls_back_to_any_language():
    descriptions = [
        123,
        {
            "lang": "en",
            "value": None,
        },
        {
            "lang": "fr",
            "value": "",
        },
        {
            "lang": "de",
            "value": "Deutsche Beschreibung",
        },
    ]

    assert get_preffered_description(
        descriptions
    ) == "Deutsche Beschreibung"


def test_description_returns_empty_without_valid_text():
    descriptions = [
        None,
        123,
        {},
        {
            "lang": "en",
            "value": "",
        },
        {
            "lang": "fr",
            "value": None,
        },
    ]

    assert get_preffered_description(
        descriptions
    ) == ""


@pytest.mark.parametrize(
    "metrics",
    [
        None,
        [],
        "cvssMetricV31",
    ],
)
def test_cvss_metrics_require_dictionary(
    metrics,
):
    assert get_preffered_cvss_matrics(
        metrics
    ) is None


def test_cvss_metrics_prefer_version_four():
    version_four = {
        "baseScore": 9.9,
        "baseSeverity": "CRITICAL",
    }

    version_three = {
        "baseScore": 8.8,
        "baseSeverity": "HIGH",
    }

    result = get_preffered_cvss_matrics({
        "cvssMetricV40": [
            {
                "cvssData": version_four,
            },
        ],
        "cvssMetricV31": [
            {
                "cvssData": version_three,
            },
        ],
    })

    assert result is version_four


def test_cvss_metrics_fall_back_to_version_three_one():
    version_three_one = {
        "baseScore": 8.1,
        "baseSeverity": "HIGH",
    }

    result = get_preffered_cvss_matrics({
        "cvssMetricV40": [],
        "cvssMetricV31": [
            {
                "cvssData": version_three_one,
            },
        ],
    })

    assert result is version_three_one


def test_cvss_metrics_skip_invalid_first_entry():
    version_three_zero = {
        "baseScore": 7.5,
        "baseSeverity": "HIGH",
    }

    result = get_preffered_cvss_matrics({
        "cvssMetricV40": "invalid",
        "cvssMetricV31": [
            None,
        ],
        "cvssMetricV30": [
            {
                "cvssData": version_three_zero,
            },
        ],
    })

    assert result is version_three_zero


def test_cvss_metrics_skip_invalid_cvss_data():
    version_two = {
        "baseScore": 5.0,
    }

    result = get_preffered_cvss_matrics({
        "cvssMetricV40": [
            {
                "cvssData": None,
            },
        ],
        "cvssMetricV31": [
            {
                "cvssData": "invalid",
            },
        ],
        "cvssMetricV2": [
            {
                "cvssData": version_two,
            },
        ],
    })

    assert result is version_two


def test_cvss_metrics_return_none_without_valid_data():
    result = get_preffered_cvss_matrics({
        "cvssMetricV40": [],
        "cvssMetricV31": [
            None,
        ],
        "cvssMetricV30": [
            {
                "cvssData": None,
            },
        ],
        "cvssMetricV2": "invalid",
    })

    assert result is None


@pytest.mark.parametrize(
    "references",
    [
        None,
        {},
        "https://example.com",
    ],
)
def test_references_require_list(
    references,
):
    assert get_reference_links(
        references
    ) == []


def test_references_filter_and_deduplicate_urls():
    references = [
        None,
        123,
        {},
        {
            "url": None,
        },
        {
            "url": "",
        },
        {
            "url": "https://example.com/one",
        },
        {
            "url": "https://example.com/two",
        },
        {
            "url": "https://example.com/one",
        },
    ]

    assert get_reference_links(
        references
    ) == [
        "https://example.com/one",
        "https://example.com/two",
    ]


def test_references_return_empty_without_valid_url():
    references = [
        None,
        {},
        {
            "url": "",
        },
        {
            "url": 123,
        },
    ]

    assert get_reference_links(
        references
    ) == []
