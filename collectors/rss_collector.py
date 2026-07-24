import feedparser


print("RSS Collector Started")
RSS_FEEDS={

  "https://feeds.feedburner.com/TheHackersNews",
  "https://www.bleepingcomputer.com/feed/",
  "https://blog.talosintelligence.com/rss/",
}

def collect_articles():
  articles = []
  for feed_url in RSS_FEEDS:
    feed = feedparser.parse(feed_url)
    for entry in feed.entries:
      article = {
        "title":entry.get("title",""),
        "link":entry.get("link",""),
        "published":entry.get("published",""),
        "summary":entry.get("summary","")
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

  



