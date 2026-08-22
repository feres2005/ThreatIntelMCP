import pytest
import requests

import collectors.github_collector as service


pytestmark = pytest.mark.unit


def test_github_fetch_handles_request_failure(
    monkeypatch,
):
    def fail_request(*arguments, **options):
        raise requests.RequestException(
            "Controlled GitHub outage."
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        fail_request,
    )

    assert service.fetch_github_advisories_page() == (
        None,
        None,
    )


def test_github_synchronization_reports_fetch_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_latest_github_advisory_updated_at",
        lambda: None,
    )
    monkeypatch.setattr(
        service,
        "fetch_github_advisories_page",
        lambda **arguments: (None, None),
    )

    result = (
        service.synchronize_all_github_advisories()
    )

    assert result["status"] == "failed"
    assert result["synchronization_mode"] == "full"
    assert result["batch_count"] == 0
    assert result["fetched_advisory_count"] == 0
    assert result["saved_advisory_count"] == 0
    assert result["saved_vulnerability_count"] == 0
    assert result["failure_count"] == 1
    assert result["failures"] == [
        {
            "stage": "fetch",
            "batch_number": 1,
            "cursor": None,
            "error": (
                "GitHub advisory page fetch "
                "failed. Review application "
                "logs for details."
            ),
        }
    ]
