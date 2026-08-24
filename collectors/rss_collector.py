import feedparser
from datetime import datetime, timezone
import feedparser
import requests
from datetime import datetime, timezone
RSS_FEEDS = {
  "https://feeds.feedburner.com/TheHackersNews": "the_hacker_news",
  "https://www.bleepingcomputer.com/feed/": "bleeping_computer",
  "https://blog.talosintelligence.com/rss/": "cisco_talos",
}
RSS_REQUEST_TIMEOUT_SECONDS = 15
RSS_REQUEST_HEADERS = {
  "User-Agent": (
    "Mozilla/5.0 "
    "(compatible; ThreatIntelMCP/1.0; "
    "+https://github.com/feres2005/"
    "ThreatIntelMCP)"
  ),
  "Accept": (
    "application/rss+xml, "
    "application/xml, "
    "text/xml;q=0.9, "
    "*/*;q=0.8"
  ),
}


def parse_entry_publication_date(entry):
   parsed_date=(
      entry.get("published_parsed")
      or entry.get("updated_parsed")
      )
   if parsed_date is None:
      return None
   return datetime(*parsed_date[:6],tzinfo=timezone.utc)

def download_feed(feed_url):
  response = requests.get(
    feed_url,
    headers=RSS_REQUEST_HEADERS,
    timeout=RSS_REQUEST_TIMEOUT_SECONDS,
  )
  response.raise_for_status()

  return response.content

def collect_articles():
  articles = []
  for feed_url, source in RSS_FEEDS.items():
    feed_content = download_feed(feed_url)
    feed = feedparser.parse(feed_content)
    for entry in feed.entries:
      article = {
        "title":entry.get("title",""),
        "link":entry.get("link",""),
        "published": parse_entry_publication_date(entry),
        "summary":entry.get("summary",""),
        "source":source
      }
      articles.append(article)

  return articles
if __name__ == "__main__":
    articles = collect_articles()

    print(f"Collected {len(articles)} articles\n")

    for article in articles[:5]:
        print("Title:", article["title"])
        print("Link:", article["link"])
        print("Published:", article["published"])
        print("-" * 50)

  



