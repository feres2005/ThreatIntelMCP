
from enrichment.cve_enricher import fetch_cve_from_nvd, normalize_cve_data
from ai.analyzer import analyze_article
from collectors.rss_collector import collect_articles
from database.github_advisory_repository import *
from database.article_repository import *
from collectors.mitre_collector import collect_mitre_techniques

from database.cve_repository import *

from database.threat_search import *

def run_ingestion_pipeline():
  print("Starting the ingestion pipeline...")
  print("synchronizing MITRE ATT&CK techniques...")
  for domain in ["enterprise-attack","mobile-attack","ics-attack"]:
    saved_count=collect_mitre_techniques(domain)
    print(f"{domain}: {saved_count} techniques synchronized")
  articles = collect_articles()
  print(f'Collected {len(articles)} articles \n')

  for article in articles:
    insert_article(article)
  
  total = count_articles()
  print("ingestion completed")
  print("the total number of articles in the database is:", total)
  unprocessed_articles = get_unprocessed_articles(1)

  if len(unprocessed_articles)>0:
    article=unprocessed_articles[0]

#this is used to call the LLM
    analysis=analyze_article(article)
    if analysis is None:
      print('analysis failed skipping article')
      return
    save_article_analysis(analysis)


    #checking if there are cves(enrichement) else skip them and print a message 
    cves=analysis["cves"]
    
    if not cves:
      print("no cves found, skipping enrichment")
    else:
      try:
        for cve_id in cves:
          print(f"enriching CVE:{cve_id}")
          raw_cve_data=fetch_cve_from_nvd(cve_id)
          if raw_cve_data is None:
            print(f"failed to fetch cve data for {cve_id}")
            return
       
          normalize_cve=normalize_cve_data(raw_cve_data)
          if normalize_cve is None:
            print(f"failed to normalize cve data for {cve_id}")
            return
        
          save_cve_enrichment(normalize_cve)
          print(f"CVE enriched and saved:{cve_id}")
      except Exception as e:
        print(f"enrichment failed for {cve_id}:{e}")
        return

    print(analysis)
    mark_article_as_processed(article.id)
    print("article marked as processed")
  else:
    print("no unprocessed articles found")


if __name__ == "__main__":
  run_ingestion_pipeline()
  print(get_latest_github_advisory_updated_at())



