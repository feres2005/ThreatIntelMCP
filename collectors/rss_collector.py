import feedparser
from datetime import datetime, timezone

print("RSS Collector Started")
RSS_FEEDS = {
  "https://feeds.feedburner.com/TheHackersNews": "the_hacker_news",
  "https://www.bleepingcomputer.com/feed/": "bleeping_computer",
  "https://blog.talosintelligence.com/rss/": "cisco_talos",
}

def parse_entry_publication_date(entry):
   parsed_date=(
      entry.get("published_parsed")
      or entry.get("updated_parsed")
      )
   if parsed_date is None:
      return None
   return datetime(*parsed_date[:6],tzinfo=timezone.utc)

def collect_articles():
  articles = []
  for feed_url, source in RSS_FEEDS.items():
    feed = feedparser.parse(feed_url)
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

  



