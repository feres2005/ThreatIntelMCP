--
-- PostgreSQL database dump
--

\restrict p3Sg9uIIf05KaeKkFKtYgQcNwLJaN1Ncfui5TK6A5XfSBVaFBW1oOPwuUMazv3h

-- Dumped from database version 18.4
-- Dumped by pg_dump version 18.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: article_analysis; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.article_analysis (
    article_id integer NOT NULL,
    summary text,
    classification jsonb,
    severity text,
    confidence_score numeric,
    malware jsonb,
    cves jsonb,
    iocs jsonb,
    mitre_techniques jsonb,
    apt_groups jsonb,
    targeted_sectors jsonb,
    affected_technologies jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: article_analysis_article_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.article_analysis_article_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: article_analysis_article_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.article_analysis_article_id_seq OWNED BY public.article_analysis.article_id;


--
-- Name: articles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.articles (
    id integer NOT NULL,
    title text NOT NULL,
    link text NOT NULL,
    published timestamp without time zone,
    summary text,
    processed boolean DEFAULT false
);


--
-- Name: articles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.articles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: articles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.articles_id_seq OWNED BY public.articles.id;


--
-- Name: cve_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cve_enrichment (
    cve_id text NOT NULL,
    description text,
    cvss_score double precision,
    severity text,
    published timestamp without time zone,
    last_modified timestamp without time zone,
    reference_links jsonb,
    enriched_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: github_advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.github_advisories (
    ghsa_id text NOT NULL,
    cve_id text,
    type text,
    summary text,
    description text,
    severity text,
    published_at timestamp without time zone,
    updated_at timestamp without time zone,
    github_reviewed_at timestamp without time zone,
    nvd_published_at timestamp without time zone,
    withdrawn_at timestamp without time zone,
    cvss_v3_score numeric,
    cvss_v3_vector text,
    cvss_v4_score numeric,
    cvss_v4_vector text,
    cwe_ids text[],
    reference_links jsonb
);


--
-- Name: github_advisory_vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.github_advisory_vulnerabilities (
    id integer NOT NULL,
    ghsa_id text NOT NULL,
    ecosystem text,
    package_name text,
    vulnerable_version_range text,
    first_patched_version text,
    vulnerable_functions text[]
);


--
-- Name: github_advisory_vulnerabilities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.github_advisory_vulnerabilities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: github_advisory_vulnerabilities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.github_advisory_vulnerabilities_id_seq OWNED BY public.github_advisory_vulnerabilities.id;


--
-- Name: mitre_techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mitre_techniques (
    stix_id text NOT NULL,
    technique_id text NOT NULL,
    domain text NOT NULL,
    name text NOT NULL,
    description text,
    is_subtechnique boolean DEFAULT false,
    platforms jsonb,
    kill_chain_phases jsonb,
    created timestamp without time zone,
    modified timestamp without time zone,
    revoked boolean DEFAULT false,
    deprecated boolean DEFAULT false,
    version text,
    reference_links jsonb
);


--
-- Name: otx_indicators; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.otx_indicators (
    indicator text NOT NULL,
    indicator_type text NOT NULL,
    reputation integer,
    pulse_count integer DEFAULT 0,
    country text,
    country_code text,
    asn text,
    malware_families jsonb DEFAULT '[]'::jsonb,
    adversaries jsonb DEFAULT '[]'::jsonb,
    industries jsonb DEFAULT '[]'::jsonb,
    validation jsonb DEFAULT '[]'::jsonb,
    sections jsonb DEFAULT '[]'::jsonb,
    last_checked timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: article_analysis article_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.article_analysis ALTER COLUMN article_id SET DEFAULT nextval('public.article_analysis_article_id_seq'::regclass);


--
-- Name: articles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.articles ALTER COLUMN id SET DEFAULT nextval('public.articles_id_seq'::regclass);


--
-- Name: github_advisory_vulnerabilities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_advisory_vulnerabilities ALTER COLUMN id SET DEFAULT nextval('public.github_advisory_vulnerabilities_id_seq'::regclass);


--
-- Name: article_analysis article_analysis_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.article_analysis
    ADD CONSTRAINT article_analysis_pkey PRIMARY KEY (article_id);


--
-- Name: articles articles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.articles
    ADD CONSTRAINT articles_pkey PRIMARY KEY (id);


--
-- Name: cve_enrichment cve_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cve_enrichment
    ADD CONSTRAINT cve_enrichment_pkey PRIMARY KEY (cve_id);


--
-- Name: github_advisories github_advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_advisories
    ADD CONSTRAINT github_advisories_pkey PRIMARY KEY (ghsa_id);


--
-- Name: github_advisory_vulnerabilities github_advisory_vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_advisory_vulnerabilities
    ADD CONSTRAINT github_advisory_vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: mitre_techniques mitre_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_techniques
    ADD CONSTRAINT mitre_techniques_pkey PRIMARY KEY (stix_id);


--
-- Name: mitre_techniques mitre_techniques_technique_id_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mitre_techniques
    ADD CONSTRAINT mitre_techniques_technique_id_domain_key UNIQUE (technique_id, domain);


--
-- Name: otx_indicators otx_indicators_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.otx_indicators
    ADD CONSTRAINT otx_indicators_pkey PRIMARY KEY (indicator, indicator_type);


--
-- Name: articles unique_article_link; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.articles
    ADD CONSTRAINT unique_article_link UNIQUE (link);


--
-- Name: article_analysis fk_article_analysis_article; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.article_analysis
    ADD CONSTRAINT fk_article_analysis_article FOREIGN KEY (article_id) REFERENCES public.articles(id) ON DELETE CASCADE;


--
-- Name: github_advisory_vulnerabilities fk_github_advisory; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_advisory_vulnerabilities
    ADD CONSTRAINT fk_github_advisory FOREIGN KEY (ghsa_id) REFERENCES public.github_advisories(ghsa_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict p3Sg9uIIf05KaeKkFKtYgQcNwLJaN1Ncfui5TK6A5XfSBVaFBW1oOPwuUMazv3h

