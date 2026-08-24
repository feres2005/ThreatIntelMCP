import json
import logging

import pytest

import scripts.run_automation_cycle as service


pytestmark = pytest.mark.unit


def test_main_configures_logging_and_runs_cycle(
    monkeypatch,
    caplog,
    capsys,
):
    configuration_calls = []
    cycle_calls = []

    monkeypatch.setattr(
        service,
        "configure_logging",
        lambda: configuration_calls.append(
            True
        ),
    )

    timestamps = iter([
        10.0,
        12.25,
    ])

    monkeypatch.setattr(
        service,
        "perf_counter",
        lambda: next(timestamps),
    )

    def fake_run_automation_cycle(**kwargs):
        cycle_calls.append(kwargs)

        return {
            "operation": (
                "run_automation_cycle"
            ),
            "status": "completed",
        }

    monkeypatch.setattr(
        service,
        "run_automation_cycle",
        fake_run_automation_cycle,
    )

    with caplog.at_level(
        logging.INFO,
        logger=service.__name__,
    ):
        exit_code = service.main([
            "--processing-limit",
            "3",
            "--embedding-limit",
            "7",
        ])

    assert exit_code == 0
    assert configuration_calls == [True]
    assert cycle_calls == [
        {
            "processing_limit": 3,
            "embedding_limit": 7,
            "include_otx": False,
            "include_cve": False,
        }
    ]

    output = json.loads(
        capsys.readouterr().out
    )

    assert output["status"] == "completed"
    assert (
        "Automation cycle started"
        in caplog.text
    )
    assert (
        "Automation cycle finished with "
        "status completed in 2.250 seconds"
        in caplog.text
    )


def test_main_logs_unexpected_cycle_failure(
    monkeypatch,
    caplog,
):
    monkeypatch.setattr(
        service,
        "configure_logging",
        lambda: None,
    )

    timestamps = iter([
        20.0,
    ])

    monkeypatch.setattr(
        service,
        "perf_counter",
        lambda: next(timestamps),
    )

    def failing_cycle(**kwargs):
        raise RuntimeError(
            "Controlled CLI failure."
        )

    monkeypatch.setattr(
        service,
        "run_automation_cycle",
        failing_cycle,
    )

    with caplog.at_level(
        logging.ERROR,
        logger=service.__name__,
    ):
        with pytest.raises(
            RuntimeError,
            match="Controlled CLI failure",
        ):
            service.main([])

    error_records = [
        record
        for record in caplog.records
        if record.levelno == logging.ERROR
    ]

    assert len(error_records) == 1
    assert (
        "failed before producing a "
        "structured result"
        in error_records[0].getMessage()
    )
    assert error_records[0].exc_info is not None