def normalize_text(value):
  if not isinstance(value, str):
    return ""
  return " ".join(value.strip())
import hashlib

def build_article_passage(title,rss_summary=None,ai_summary=None):
  clean_title=normalize_text(title)
  if not clean_title:
    raise ValueError("Title must be a non-empty string")

  clean_rss_summary=normalize_text(rss_summary)
  clean_ai_summary=normalize_text(ai_summary)

  selected_summary=clean_ai_summary or clean_rss_summary

  passage_parts=[f"Title: {clean_title}"]

  if selected_summary:
    passage_parts.append(f"Summary: {selected_summary}")

  return"\n".join(passage_parts)

def calculate_content_hash(content):
   if not isinstance(content,str) or not content.strip():
    raise ValueError("Content must be a non-empty string")

   return hashlib.sha256(content.encode("utf-8")).hexdigest()
