from functools import lru_cache


EMBEDDING_MODEL_NAME = "intfloat/multilingual-e5-small"


@lru_cache(maxsize=1)
def get_embedding_model():
  from sentence_transformers import SentenceTransformer

  model = SentenceTransformer(
    EMBEDDING_MODEL_NAME,
    local_files_only=True,
  )
  return model


def generate_embedding(text: str, text_type: str) -> list[float]:
  if not isinstance(text, str) or not text.strip():
    raise ValueError("Text must be a non-empty string.")

  if text_type not in {"query", "passage"}:
    raise ValueError(
      "text_type must be either 'query' or 'passage'."
    )

  prefixed_text = f"{text_type}: {text.strip()}"

  model = get_embedding_model()
  embedding = model.encode(
    prefixed_text,
    normalize_embeddings=True,
  )

  return embedding.tolist()
