BEGIN;

ALTER TABLE public.articles
ADD COLUMN source text;

UPDATE public.articles
SET source = CASE
    WHEN LOWER(
        SUBSTRING(link FROM '^https?://([^/]+)')
    ) = 'thehackernews.com'
        THEN 'the_hacker_news'

    WHEN LOWER(
        SUBSTRING(link FROM '^https?://([^/]+)')
    ) = 'www.bleepingcomputer.com'
        THEN 'bleeping_computer'

    WHEN LOWER(
        SUBSTRING(link FROM '^https?://([^/]+)')
    ) = 'blog.talosintelligence.com'
        THEN 'cisco_talos'
END;

ALTER TABLE public.articles
ALTER COLUMN source SET NOT NULL;

COMMIT;