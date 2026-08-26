import json
import os
import asyncio
import sys
from pathlib import Path
import subprocess

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKER_TIMEOUT_SECONDS = 120
def _run_worker_synchronously(
  search_query,
  limit,
  environment,
):
  arguments = [
    sys.executable,
    "-m",
    "semantic_search.search_worker",
    search_query,
    str(limit),
  ]

  try:
    completed_process = subprocess.run(
      arguments,
      cwd=str(PROJECT_ROOT),
      env=environment,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      timeout=WORKER_TIMEOUT_SECONDS,
      check=False,
      shell=False,
    )
  except subprocess.TimeoutExpired as error:
    raise RuntimeError(
      "Semantic search worker timed out."
    ) from error

  return (
    completed_process.returncode,
    completed_process.stdout,
    completed_process.stderr,
  )

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

  try:
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
  except NotImplementedError:
    (
      returncode,
      stdout,
      stderr,
    ) = await asyncio.to_thread(
      _run_worker_synchronously,
      search_query,
      limit,
      environment,
    )
  else:
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

    returncode = process.returncode
  if returncode != 0:
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