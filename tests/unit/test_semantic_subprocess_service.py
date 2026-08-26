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


def test_worker_uses_synchronous_fallback_when_needed(
    monkeypatch,
):
    async def unsupported_create(*args, **kwargs):
        raise NotImplementedError

    calls = []

    def fake_run(arguments, **options):
        calls.append({
            "arguments": arguments,
            "options": options,
        })

        return service.subprocess.CompletedProcess(
            args=arguments,
            returncode=0,
            stdout=b'[{"article_id": 2563}]',
            stderr=b"",
        )

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        unsupported_create,
    )
    monkeypatch.setattr(
        service.subprocess,
        "run",
        fake_run,
    )

    result = asyncio.run(
        service.run_semantic_search_worker(
            "controlled Windows query",
            4,
        )
    )

    assert result == [{"article_id": 2563}]
    assert len(calls) == 1

    call = calls[0]

    assert call["arguments"] == [
        service.sys.executable,
        "-m",
        "semantic_search.search_worker",
        "controlled Windows query",
        "4",
    ]
    assert call["options"]["timeout"] == (
        service.WORKER_TIMEOUT_SECONDS
    )
    assert call["options"]["shell"] is False


def test_synchronous_fallback_maps_timeout(
    monkeypatch,
):
    async def unsupported_create(*args, **kwargs):
        raise NotImplementedError

    def fake_run(arguments, **options):
        raise service.subprocess.TimeoutExpired(
            cmd=arguments,
            timeout=options["timeout"],
        )

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        unsupported_create,
    )
    monkeypatch.setattr(
        service.subprocess,
        "run",
        fake_run,
    )

    with pytest.raises(
        RuntimeError,
        match="Semantic search worker timed out.",
    ):
        asyncio.run(
            service.run_semantic_search_worker(
                "controlled timeout query",
                3,
            )
        )



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

def test_worker_timeout_reaps_real_child_process(
    monkeypatch,
):
    original_create_subprocess = (
        asyncio.create_subprocess_exec
    )
    captured = {}

    async def create_controlled_child(
        *arguments,
        **options,
    ):
        process = await original_create_subprocess(
            service.sys.executable,
            "-c",
            "import time; time.sleep(60)",
            cwd=options["cwd"],
            env=options["env"],
            stdin=options["stdin"],
            stdout=options["stdout"],
            stderr=options["stderr"],
        )
        captured["process"] = process
        return process

    monkeypatch.setattr(
        service.asyncio,
        "create_subprocess_exec",
        create_controlled_child,
    )
    monkeypatch.setattr(
        service,
        "WORKER_TIMEOUT_SECONDS",
        0.1,
    )

    with pytest.raises(
        RuntimeError,
        match="Semantic search worker timed out.",
    ):
        asyncio.run(
            service.run_semantic_search_worker(
                "controlled timeout query",
                3,
            )
        )

    process = captured["process"]

    assert process.returncode is not None
    assert process.returncode != 0