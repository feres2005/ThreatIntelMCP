from ai.analyzer import analyze_article
from database.article_repository import (
    mark_article_as_processed,
    save_article_analysis,
)
from database.article_ioc_repository import (
    replace_article_iocs,
)
from enrichment.ioc_normalizer import (
    normalize_ioc_list,
)
from enrichment.otx_lookup_service import (
    lookup_otx_indicators,
)
from enrichment.cve_lookup_service import (
    lookup_cve,
)


def _validate_article_id(article_id):
    if (
        not isinstance(article_id, int)
        or isinstance(article_id, bool)
        or article_id <= 0
    ):
        raise ValueError(
            "Article ID must be a positive integer."
        )

def analyze_and_save_article(article):
    if article is None or not hasattr(
        article,
        "id",
    ):
        raise ValueError(
            "A database article row is required."
        )

    article_id = article.id

    _validate_article_id(article_id)

    analysis = analyze_article(article)

    if analysis is None:
        return {
            "article_id": article_id,
            "status": "analysis_failed",
            "analysis": None,
        }

    if not isinstance(analysis, dict):
        raise ValueError(
            "Article analysis must be a dictionary."
        )

    if analysis.get("article_id") != article_id:
        raise ValueError(
            "Article analysis ID does not match "
            "the requested article."
        )

    save_article_analysis(analysis)

    return {
        "article_id": article_id,
        "status": "analysis_saved",
        "analysis": analysis,
    }

def normalize_and_store_article_iocs(
    article_id,
    analysis,
):
    _validate_article_id(article_id)

    if not isinstance(analysis, dict):
        raise ValueError(
            "Article analysis must be a dictionary."
        )

    if analysis.get("article_id") != article_id:
        raise ValueError(
            "Article analysis ID does not match "
            "the requested article."
        )

    raw_iocs = analysis.get("iocs", [])

    normalized_iocs = normalize_ioc_list(
        raw_iocs
    )

    replacement_result = replace_article_iocs(
        article_id,
        normalized_iocs,
    )

    return {
        "article_id": article_id,
        "raw_ioc_count": len(raw_iocs),
        "normalized_ioc_count": len(
            normalized_iocs
        ),
        "normalized_iocs": normalized_iocs,
        "replacement_result": (
            replacement_result
        ),
    }

def enrich_article_iocs(
    article_id,
    normalized_iocs,
    include_otx=True,
):
    _validate_article_id(article_id)

    if not isinstance(normalized_iocs, list):
        raise ValueError(
            "Normalized IOCs must be provided "
            "as a list."
        )

    if not isinstance(include_otx, bool):
        raise ValueError(
            "include_otx must be a boolean."
        )

    if not include_otx:
        return {
            "article_id": article_id,
            "status": "disabled",
            "lookup_count": 0,
            "successful_lookup_count": 0,
            "failed_lookup_count": 0,
            "results": [],
        }

    if not normalized_iocs:
        return {
            "article_id": article_id,
            "status": "no_iocs",
            "lookup_count": 0,
            "successful_lookup_count": 0,
            "failed_lookup_count": 0,
            "results": [],
        }

    results = lookup_otx_indicators(
        normalized_iocs
    )

    successful_lookup_count = sum(
        result is not None
        for result in results
    )

    return {
        "article_id": article_id,
        "status": "completed",
        "lookup_count": len(
            normalized_iocs
        ),
        "successful_lookup_count": (
            successful_lookup_count
        ),
        "failed_lookup_count": (
            len(normalized_iocs)
            - successful_lookup_count
        ),
        "results": results,
    }

def enrich_article_cves(
    article_id,
    analysis,
    include_cve=True,
):
    _validate_article_id(article_id)

    if not isinstance(analysis, dict):
        raise ValueError(
            "Article analysis must be a dictionary."
        )

    if analysis.get("article_id") != article_id:
        raise ValueError(
            "Article analysis ID does not match "
            "the requested article."
        )

    if not isinstance(include_cve, bool):
        raise ValueError(
            "include_cve must be a boolean."
        )

    cve_ids = analysis.get("cves", [])

    if not isinstance(cve_ids, list):
        raise ValueError(
            "Article CVEs must be provided "
            "as a list."
        )

    for cve_id in cve_ids:
        if (
            not isinstance(cve_id, str)
            or not cve_id.strip()
        ):
            raise ValueError(
                "Each CVE ID must be a "
                "non-empty string."
            )

    unique_cve_ids = list(
        dict.fromkeys(cve_ids)
    )

    if not include_cve:
        return {
            "article_id": article_id,
            "status": "disabled",
            "requested_cve_count": len(
                cve_ids
            ),
            "lookup_count": 0,
            "available_count": 0,
            "unavailable_count": 0,
            "failed_count": 0,
            "results": [],
        }

    if not unique_cve_ids:
        return {
            "article_id": article_id,
            "status": "no_cves",
            "requested_cve_count": 0,
            "lookup_count": 0,
            "available_count": 0,
            "unavailable_count": 0,
            "failed_count": 0,
            "results": [],
        }

    results = []

    for cve_id in unique_cve_ids:
        try:
            details = lookup_cve(cve_id)
        except Exception as error:
            results.append({
                "cve_id": cve_id,
                "enrichment_available": False,
                "details": None,
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            })
            continue

        results.append({
            "cve_id": cve_id,
            "enrichment_available": (
                details is not None
            ),
            "details": details,
            "error": None,
        })

    available_count = sum(
        result["enrichment_available"]
        for result in results
    )

    failed_count = sum(
        result["error"] is not None
        for result in results
    )

    unavailable_count = (
        len(results)
        - available_count
        - failed_count
    )

    return {
        "article_id": article_id,
        "status": "completed",
        "requested_cve_count": len(cve_ids),
        "lookup_count": len(unique_cve_ids),
        "available_count": available_count,
        "unavailable_count": unavailable_count,
        "failed_count": failed_count,
        "results": results,
    }

def process_article(
    article,
    include_otx=True,
    include_cve=True,
):
    if not isinstance(include_otx, bool):
        raise ValueError(
            "include_otx must be a boolean."
        )

    if not isinstance(include_cve, bool):
        raise ValueError(
            "include_cve must be a boolean."
        )

    analysis_result = analyze_and_save_article(
        article
    )

    article_id = analysis_result["article_id"]

    if (
        analysis_result["status"]
        == "analysis_failed"
    ):
        return {
            "article_id": article_id,
            "status": "analysis_failed",
            "analysis": None,
            "ioc_processing": None,
            "otx_enrichment": None,
            "cve_enrichment": None,
            "embedding_status": "deferred",
            "marked_processed": False,
            "warnings": [
                "The AI analysis did not produce "
                "a safe result."
            ],
        }

    analysis = analysis_result["analysis"]

    ioc_processing = (
        normalize_and_store_article_iocs(
            article_id,
            analysis,
        )
    )

    warnings = []

    try:
        otx_enrichment = enrich_article_iocs(
            article_id,
            ioc_processing[
                "normalized_iocs"
            ],
            include_otx=include_otx,
        )
    except Exception as error:
        otx_enrichment = {
            "article_id": article_id,
            "status": "failed",
            "lookup_count": 0,
            "successful_lookup_count": 0,
            "failed_lookup_count": 0,
            "results": [],
            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }

        warnings.append(
            "OTX enrichment failed unexpectedly."
        )
    else:
        if (
            otx_enrichment[
                "failed_lookup_count"
            ]
            > 0
        ):
            warnings.append(
                "One or more OTX lookups "
                "returned no enrichment."
            )

    try:
        cve_enrichment = enrich_article_cves(
            article_id,
            analysis,
            include_cve=include_cve,
        )
    except Exception as error:
        cve_enrichment = {
            "article_id": article_id,
            "status": "failed",
            "requested_cve_count": 0,
            "lookup_count": 0,
            "available_count": 0,
            "unavailable_count": 0,
            "failed_count": 0,
            "results": [],
            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }

        warnings.append(
            "CVE enrichment failed unexpectedly."
        )
    else:
        if cve_enrichment["failed_count"] > 0:
            warnings.append(
                "One or more CVE lookups failed."
            )

    mark_article_as_processed(article_id)

    status = (
        "processed_with_warnings"
        if warnings
        else "processed"
    )

    return {
        "article_id": article_id,
        "status": status,
        "analysis": analysis,
        "ioc_processing": ioc_processing,
        "otx_enrichment": otx_enrichment,
        "cve_enrichment": cve_enrichment,
        "embedding_status": "deferred",
        "marked_processed": True,
        "warnings": warnings,
    }