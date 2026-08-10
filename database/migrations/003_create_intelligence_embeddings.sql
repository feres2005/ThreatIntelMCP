CREATE EXTENSION  IF NOT EXISTS vector;

CREATE TABLE intelligence_embeddings (
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  embedding vector(384) NOT NULL,
  embedding_model TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  embedded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(entity_type,entity_id)
);
