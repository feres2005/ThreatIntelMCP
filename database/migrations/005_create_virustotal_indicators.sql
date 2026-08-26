CREATE TABLE IF NOT EXISTS public.virustotal_indicators (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    report_available BOOLEAN NOT NULL DEFAULT TRUE,
    resource_type TEXT,
    resource_id TEXT,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    suspicious_count INTEGER NOT NULL DEFAULT 0,
    harmless_count INTEGER NOT NULL DEFAULT 0,
    undetected_count INTEGER NOT NULL DEFAULT 0,
    timeout_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    type_unsupported_count INTEGER NOT NULL DEFAULT 0,
    confirmed_timeout_count INTEGER NOT NULL DEFAULT 0,
    total_engine_count INTEGER NOT NULL DEFAULT 0,
    total_result_count INTEGER NOT NULL DEFAULT 0,
    reputation INTEGER,
    community_votes JSONB NOT NULL
        DEFAULT '{}'::JSONB,
    detections JSONB NOT NULL
        DEFAULT '[]'::JSONB,
    categories JSONB NOT NULL
        DEFAULT '[]'::JSONB,
    tags JSONB NOT NULL
        DEFAULT '[]'::JSONB,
    names JSONB NOT NULL
        DEFAULT '[]'::JSONB,
    meaningful_name TEXT,
    file_type TEXT,
    country TEXT,
    asn BIGINT,
    as_owner TEXT,
    last_analysis_date TIMESTAMP WITH TIME ZONE,
    permalink TEXT,
    last_checked TIMESTAMP WITH TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (
        indicator,
        indicator_type
    ),

    CONSTRAINT virustotal_indicator_not_empty
        CHECK (BTRIM(indicator) <> ''),

    CONSTRAINT virustotal_indicator_type_valid
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
        ),

    CONSTRAINT virustotal_resource_present
        CHECK (
            NOT report_available
            OR (
                resource_type IS NOT NULL
                AND resource_id IS NOT NULL
            )
        ),

    CONSTRAINT virustotal_counts_nonnegative
        CHECK (
            malicious_count >= 0
            AND suspicious_count >= 0
            AND harmless_count >= 0
            AND undetected_count >= 0
            AND timeout_count >= 0
            AND failure_count >= 0
            AND type_unsupported_count >= 0
            AND confirmed_timeout_count >= 0
            AND total_engine_count >= 0
            AND total_result_count >= 0
        ),

    CONSTRAINT virustotal_engine_count_consistent
        CHECK (
            total_engine_count = (
                malicious_count
                + suspicious_count
                + harmless_count
                + undetected_count
            )
        ),

    CONSTRAINT virustotal_result_count_consistent
        CHECK (
            total_result_count = (
                malicious_count
                + suspicious_count
                + harmless_count
                + undetected_count
                + timeout_count
                + failure_count
                + type_unsupported_count
                + confirmed_timeout_count
            )
        )
);

CREATE INDEX IF NOT EXISTS
    idx_virustotal_indicators_last_checked
ON public.virustotal_indicators (
    last_checked DESC
);