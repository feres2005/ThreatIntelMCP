CREATE TABLE public.article_iocs(
  article_id INTEGER NOT NULL,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL
      DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(
    article_id,
    indicator,
    indicator_type
  ),

  CONSTRAINT fk_article_iocs_article
      FOREIGN KEY(article_id)
      REFERENCES PUBLIC.articles(id)
      ON DELETE CASCADE,

  CONSTRAINT article_iocs_indicator_not_empty
    CHECK(BTRIM(indicator)<> ''),

  CONSTRAINT article_iocs_type_valid
        CHECK (
            indicator_type IN (
                'IPv4',
                'IPv6',
                'domain',
                'URL',
                'FileHash-MD5',
                'FileHash-SHA1',
                'FileHash-SHA256'
            )
        )
);
CREATE INDEX idx_article_iocs_indicator
    ON public.article_iocs (
        indicator,
        indicator_type
    );