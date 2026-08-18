BEGIN;

DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'articles'
          AND column_name = 'published'
          AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE public.articles
        ALTER COLUMN published
        TYPE TIMESTAMP WITH TIME ZONE
        USING published AT TIME ZONE 'UTC';
    END IF;
END
$migration$;

COMMIT;