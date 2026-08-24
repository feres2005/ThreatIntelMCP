import logging
import sys
from logging.handlers import (
    RotatingFileHandler,
)
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_LOG_PATH = (
    PROJECT_ROOT
    / "automation_logs"
    / "threatintelmcp.log"
)

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | "
    "%(name)s | %(message)s"
)

STDERR_HANDLER_NAME = "threatintelmcp.stderr"
FILE_HANDLER_NAME = "threatintelmcp.file"

MAX_LOG_BYTES = 2 * 1024 * 1024
LOG_BACKUP_COUNT = 3


def configure_logging(
    log_path=None,
    level=logging.INFO,
):
    selected_log_path = (
        DEFAULT_LOG_PATH
        if log_path is None
        else Path(log_path)
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    existing_handler_names = {
        handler.get_name()
        for handler in root_logger.handlers
    }

    formatter = logging.Formatter(
        LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if (
        STDERR_HANDLER_NAME
        not in existing_handler_names
    ):
        stderr_handler = logging.StreamHandler(
            sys.stderr
        )
        stderr_handler.set_name(
            STDERR_HANDLER_NAME
        )
        stderr_handler.setLevel(level)
        stderr_handler.setFormatter(formatter)

        root_logger.addHandler(
            stderr_handler
        )

    if (
        FILE_HANDLER_NAME
        not in existing_handler_names
    ):
        selected_log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_handler = RotatingFileHandler(
            selected_log_path,
            maxBytes=MAX_LOG_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.set_name(
            FILE_HANDLER_NAME
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)

        root_logger.addHandler(file_handler)

    logging.captureWarnings(True)

    return root_logger