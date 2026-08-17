import json
import sys
from contextlib import redirect_stdout


def main():

  if len(sys.argv) != 3:
    raise ValueError(
      "Expected a search query and a result limit."
    )

  search_query = sys.argv[1]
  limit = int(sys.argv[2])



  with redirect_stdout(sys.stderr):
    from semantic_search.search_service import (
      semantic_search_articles,
    )


    results = semantic_search_articles(
      search_query,
      limit,
    )

  print(
    json.dumps(
      results,
      ensure_ascii=False,
    )
  )

if __name__ == "__main__":
  main()