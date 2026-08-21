import asyncio

import pytest

import semantic_search.subprocess_service as service


pytestmark = pytest.mark.unit


class ControlledProcess:
    def __init__(
        self,
        *,
        returncode=0,
        stdout=b"[]",
        stderr=b"",
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.communicate_calls = 0
        self.killed = False

    async def communicate(self):
        self.communicate_calls += 1

        return (
            self.stdout,
            self.stderr,
        )

    def kill(self):
        self.killed = True


def test_worker_returns_decoded_json(
    monkeypatch,
):
    process = ControlledProcess(
        stdout=(
            b'[{"article_id": 801, '
            b'"similarity": 0.91}]'
        ),
    )

    calls = []

    async def fake_create(
        *arguments,
        **keyword_arguments,
    ):
        calls.append({
            "arguments": arguments,
            "keyword_arguments": (
                keyword_arguments
            ),
        })

        return process

    monkeypatch.setenv(
        "CONTROLLED_PARENT_ENV",
        "preserved",
    )
    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        fake_create,
    )

    result = asyncio.run(
        service.run_semantic_search_worker(
            "ransomware targeting hospitals",
            4,
        )
    )

    assert result == [
        {
            "article_id": 801,
            "similarity": 0.91,
        },
    ]
    assert process.communicate_calls == 1
    assert process.killed is False
    assert len(calls) == 1

    call = calls[0]

    assert call["arguments"] == (
        service.sys.executable,
        "-m",
        "semantic_search.search_worker",
        "ransomware targeting hospitals",
        "4",
    )

    options = call["keyword_arguments"]

    assert options["cwd"] == str(
        service.PROJECT_ROOT
    )
    assert options["stdin"] is (
        service.asyncio.subprocess.DEVNULL
    )
    assert options["stdout"] is (
        service.asyncio.subprocess.PIPE
    )
    assert options["stderr"] is (
        service.asyncio.subprocess.PIPE
    )

    environment = options["env"]

    assert environment[
        "CONTROLLED_PARENT_ENV"
    ] == "preserved"
    assert environment[
        "PYTHONIOENCODING"
    ] == "utf-8"
    assert environment[
        "HF_HUB_DISABLE_PROGRESS_BARS"
    ] == "1"
    assert environment[
        "TRANSFORMERS_VERBOSITY"
    ] == "error"


@pytest.mark.parametrize(
    (
        "stderr",
        "expected_message",
    ),
    [
        (
            b"Controlled worker failure\n",
            "Controlled worker failure",
        ),
        (
            b"",
            "Semantic search worker failed.",
        ),
    ],
)
def test_worker_reports_nonzero_exit(
    monkeypatch,
    stderr,
    expected_message,
):
    process = ControlledProcess(
        returncode=1,
        stdout=b"",
        stderr=stderr,
    )

    async def fake_create(*args, **kwargs):
        return process

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        fake_create,
    )

    with pytest.raises(
        RuntimeError
    ) as error_info:
        asyncio.run(
            service.run_semantic_search_worker(
                "controlled query",
                3,
            )
        )

    assert str(error_info.value) == (
        expected_message
    )


@pytest.mark.parametrize(
    "stdout",
    [
        b"{invalid-json",
        b"\xff\xfe\xfa",
    ],
)
def test_worker_rejects_invalid_output(
    monkeypatch,
    stdout,
):
    process = ControlledProcess(
        returncode=0,
        stdout=stdout,
    )

    async def fake_create(*args, **kwargs):
        return process

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        fake_create,
    )

    with pytest.raises(
        RuntimeError
    ) as error_info:
        asyncio.run(
            service.run_semantic_search_worker(
                "controlled query",
                3,
            )
        )

    assert str(error_info.value) == (
        "Semantic search worker returned "
        "invalid JSON."
    )


def test_worker_timeout_kills_process(
    monkeypatch,
):
    process = ControlledProcess()

    async def fake_create(*args, **kwargs):
        return process

    wait_calls = []

    async def fake_wait_for(
        awaitable,
        *,
        timeout,
    ):
        wait_calls.append(timeout)

        awaitable.close()

        raise asyncio.TimeoutError(
            "Controlled timeout"
        )

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        fake_create,
    )
    monkeypatch.setattr(
        service.asyncio,
        "wait_for",
        fake_wait_for,
    )

    with pytest.raises(
        RuntimeError
    ) as error_info:
        asyncio.run(
            service.run_semantic_search_worker(
                "controlled query",
                3,
            )
        )

    assert str(error_info.value) == (
        "Semantic search worker timed out."
    )
    assert wait_calls == [
        service.WORKER_TIMEOUT_SECONDS,
    ]
    assert process.killed is True
    assert process.communicate_calls == 1
