import json
from bs4 import BeautifulSoup
from datetime import timezone
from dateutil.parser import isoparse
import requests
import logging
logger = logging.getLogger(__name__)
from database.article_repository import (
  get_articles_missing_publication_date,
  update_article_publication_date,
)
import time

REQUEST_DELAY_SECONDS = 1

RECOVERABLE_DATE_SOURCES = (
  "bleeping_computer",
  "cisco_talos",
)

BACKFILL_BATCH_LIMIT = 100

def parse_publication_date(raw_date):
  if not isinstance(raw_date, str) or not raw_date.strip():
    return None

  try:
    parsed_date = isoparse(raw_date.strip())
  except ValueError:
    return None

  if parsed_date.tzinfo is None:
    return None

  return parsed_date.astimezone(timezone.utc)


def find_json_ld_publication_date(data):
  if isinstance(data, dict):
    published_date = parse_publication_date(
      data.get("datePublished")
    )

    if published_date is not None:
      return published_date

    for value in data.values():
      found_date = find_json_ld_publication_date(value)

      if found_date is not None:
        return found_date

  if isinstance(data, list):
    for item in data:
      found_date = find_json_ld_publication_date(item)

      if found_date is not None:
        return found_date

  return None


def extract_json_ld_publication_date(html):
  soup = BeautifulSoup(html, "html.parser")

  scripts = soup.find_all(
    "script",
    attrs={"type": "application/ld+json"},
  )

  for script in scripts:
    raw_json = script.string or script.get_text(strip=True)

    try:
      data = json.loads(raw_json)
    except (TypeError, json.JSONDecodeError):
      continue

    published_date = find_json_ld_publication_date(data)

    if published_date is not None:
      return published_date

  return None

def fetch_article_html(article_url):
  try:
    response = requests.get(
      article_url,
      headers={
        "User-Agent": (
          "ThreatIntelMCP/1.0 "
          "historical-date-recovery"
        )
      },
      timeout=15,
    )

    response.raise_for_status()

  except requests.RequestException as error:
    logger.warning(
      "Failed to fetch %s: %s",
     article_url,
     error,
   )
    return None

  return response.text

def backfill_publication_dates(source, limit):
  articles = get_articles_missing_publication_date(
    source,
    limit,
  )

  updated_count = 0

  for article in articles:
    html = fetch_article_html(article["link"])
    time.sleep(REQUEST_DELAY_SECONDS)

    if html is None:
      print(
        f"Could not fetch article {article['article_id']}"
      )
      continue

    published = extract_json_ld_publication_date(html)

    if published is None:
      print(
        f"No JSON-LD date for article {article['article_id']}"
      )
      continue

    was_updated = update_article_publication_date(
      article["article_id"],
      published,
    )

    if was_updated:
      updated_count += 1

      print(
        f"Updated article {article['article_id']}: "
        f"{published.isoformat()}"
      )

  print(
    f"Recovered {updated_count} publication dates "
    f"for {source}."
  )


if __name__ == "__main__":
  for source in RECOVERABLE_DATE_SOURCES:
    backfill_publication_dates(
      source,
      BACKFILL_BATCH_LIMIT,
    )