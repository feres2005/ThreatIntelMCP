import logging

import pytest

import mcp_server.server as service


pytestmark = pytest.mark.unit


def test_main_configures_logging_and_runs_stdio(
    monkeypatch,
    caplog,
):
    configuration_calls = []
    run_calls = []

    monkeypatch.setattr(
        service,
        "configure_logging",
        lambda: configuration_calls.append(
            True
        ),
    )

    monkeypatch.setattr(
        service.mcp,
        "run",
        lambda **kwargs: run_calls.append(
            kwargs
        ),
    )

    with caplog.at_level(
        logging.INFO,
        logger=service.__name__,
    ):
        result = service.main()

    assert result is None
    assert configuration_calls == [True]
    assert run_calls == [
        {
            "transport": "stdio",
        }
    ]
    assert (
        "Starting ThreatIntelMCP MCP server"
        in caplog.text
    )
    assert (
        "ThreatIntelMCP MCP server stopped"
        in caplog.text
    )


def test_main_logs_fatal_mcp_failure(
    monkeypatch,
    caplog,
):
    monkeypatch.setattr(
        service,
        "configure_logging",
        lambda: None,
    )

    def failing_run(**kwargs):
        raise RuntimeError(
            "Controlled MCP failure."
        )

    monkeypatch.setattr(
        service.mcp,
        "run",
        failing_run,
    )

    with caplog.at_level(
        logging.ERROR,
        logger=service.__name__,
    ):
        with pytest.raises(
            RuntimeError,
            match="Controlled MCP failure",
        ):
            service.main()

    error_records = [
        record
        for record in caplog.records
        if record.levelno == logging.ERROR
    ]

    assert len(error_records) == 1
    assert (
        "ThreatIntelMCP MCP server failed"
        in error_records[0].getMessage()
    )
    assert error_records[0].exc_info is not None