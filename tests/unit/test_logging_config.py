import logging

import pytest

from observability.logging_config import (
    FILE_HANDLER_NAME,
    STDERR_HANDLER_NAME,
    configure_logging,
)


pytestmark = pytest.mark.unit


def _remove_application_handlers():
    root_logger = logging.getLogger()

    for handler in list(
        root_logger.handlers
    ):
        if handler.get_name() in {
            STDERR_HANDLER_NAME,
            FILE_HANDLER_NAME,
        }:
            root_logger.removeHandler(handler)
            handler.close()


def test_configure_logging_adds_handlers_once(
    tmp_path,
):
    root_logger = logging.getLogger()
    previous_level = root_logger.level

    _remove_application_handlers()

    try:
        log_path = (
            tmp_path
            / "logs"
            / "application.log"
        )

        first_result = configure_logging(
            log_path=log_path
        )
        second_result = configure_logging(
            log_path=log_path
        )

        application_handlers = [
            handler
            for handler in root_logger.handlers
            if handler.get_name() in {
                STDERR_HANDLER_NAME,
                FILE_HANDLER_NAME,
            }
        ]

        assert first_result is root_logger
        assert second_result is root_logger
        assert {
            handler.get_name()
            for handler in application_handlers
        } == {
            STDERR_HANDLER_NAME,
            FILE_HANDLER_NAME,
        }
        assert len(application_handlers) == 2
    finally:
        _remove_application_handlers()
        root_logger.setLevel(previous_level)


def test_configured_logging_writes_to_stderr_and_file(
    tmp_path,
    capsys,
):
    root_logger = logging.getLogger()
    previous_level = root_logger.level

    _remove_application_handlers()

    try:
        log_path = (
            tmp_path
            / "logs"
            / "application.log"
        )

        configure_logging(
            log_path=log_path
        )

        logger = logging.getLogger(
            "tests.controlled"
        )
        logger.warning(
            "Controlled logging message."
        )

        for handler in root_logger.handlers:
            if handler.get_name() in {
                STDERR_HANDLER_NAME,
                FILE_HANDLER_NAME,
            }:
                handler.flush()

        captured = capsys.readouterr()

        assert (
            "Controlled logging message."
            in captured.err
        )
        assert (
            "Controlled logging message."
            in log_path.read_text(
                encoding="utf-8"
            )
        )
        assert captured.out == ""
    finally:
        _remove_application_handlers()
        root_logger.setLevel(previous_level)
        