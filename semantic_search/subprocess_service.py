import json
import os
import asyncio
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKER_TIMEOUT_SECONDS = 120


async def run_semantic_search_worker(search_query, limit):
  # TODO(POST-PFE-006): Build a minimal worker
  # environment that retains DATABASE_URL while
  # excluding unrelated external API credentials.
  # This is deferred because the current worker is
  # trusted, local, and invoked without a shell.
  environment = os.environ.copy()
  environment["PYTHONIOENCODING"] = "utf-8"
  environment["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
  environment["TRANSFORMERS_VERBOSITY"] = "error"

  process = await asyncio.create_subprocess_exec(
    sys.executable,
    "-m",
    "semantic_search.search_worker",
    search_query,
    str(limit),
    cwd=str(PROJECT_ROOT),
    env=environment,
    stdin=asyncio.subprocess.DEVNULL,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
  )

  try:
    stdout, stderr = await asyncio.wait_for(
      process.communicate(),
      timeout=WORKER_TIMEOUT_SECONDS,
    )
  except asyncio.TimeoutError as error:
    process.kill()
    await process.communicate()

    raise RuntimeError(
      "Semantic search worker timed out."
    ) from error

  if process.returncode != 0:
    error_message = stderr.decode(
      "utf-8",
      errors="replace",
    ).strip()

    raise RuntimeError(
      error_message
      or "Semantic search worker failed."
    )

  try:
    return json.loads(
      stdout.decode(
        "utf-8",
        errors="strict",
      )
    )
  except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise RuntimeError(
      "Semantic search worker returned invalid JSON."
    ) from error