from scoring.scoring_service import (
    build_scoring_report,
)
from scoring.confidence_scoring import (
    score_otx_confidence,
)
from scoring.threat_scoring import (
    score_otx_threat,
)
from correlation.article_investigation_service import (
    get_article_investigation,
)
from scoring.enrichment_mapping import (
    extract_cvss_scores,
)



def build_article_scoring_report(investigation):
    if not isinstance(investigation, dict):
        raise ValueError(
            "Article investigation must be a dictionary."
        )

    article = investigation.get("article")

    if not isinstance(article, dict):
        raise ValueError(
            "Article investigation is missing article data."
        )

    article_id = article.get("article_id")
    valid_article_id = (
        isinstance(article_id, int)
        and not isinstance(article_id, bool)
        and article_id > 0
    )

    if not valid_article_id:
        raise ValueError(
            "Article scoring requires a positive "
            "integer article ID."
        )
    cve_enrichment = investigation.get(
        "cve_enrichment"
    )
    mitre_enrichment = investigation.get(
        "mitre_enrichment"
    )
    otx_selection = _select_representative_otx(
        investigation.get("ioc_enrichment")
    )

    otx_record = (
        otx_selection["otx_record"]
        if otx_selection is not None
        else None
    )

    scoring = build_scoring_report(
        article_severity=article.get("severity"),
        cvss_scores=extract_cvss_scores(
            cve_enrichment
        ),
        malware=article.get("malware"),
        apt_groups=article.get("apt_groups"),
        mitre_techniques=article.get(
            "mitre_techniques"
        ),
        article_ids=[article_id],
        ai_confidences=[
            article.get("confidence_score")
        ],
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
        otx_record=otx_record,
    )

    otx_selection_summary = None

    if otx_selection is not None:
        otx_selection_summary = {
            "indicator": otx_selection[
                "indicator"
            ],
            "indicator_type": otx_selection[
                "indicator_type"
            ],
            "selection_method": (
                "highest_threat_then_confidence"
            ),
            "threat_points": otx_selection[
                "threat_points"
            ],
            "confidence_points": otx_selection[
                "confidence_points"
            ],
        }

    return {
        "target": {
            "entity_type": "article",
            "article_id": article_id,
            "title": article.get("title"),
        },
        "otx_selection": otx_selection_summary,
        **scoring,
    }
def _select_representative_otx(
    ioc_enrichment,
):
    if not isinstance(ioc_enrichment, list):
        return None

    selected = None
    selected_rank = None

    for entry in ioc_enrichment:
        if not isinstance(entry, dict):
            continue

        otx_record = entry.get("otx_enrichment")

        if not isinstance(otx_record, dict) or not otx_record:
            continue

        threat_component = score_otx_threat(
            otx_record
        )

        confidence_component = score_otx_confidence(
            otx_record
        )

        rank = (
            threat_component["points"],
            confidence_component["points"],
        )

        if selected_rank is None or rank > selected_rank:
            selected_rank = rank
            selected = {
                "indicator": entry.get("indicator"),
                "indicator_type": entry.get(
                    "indicator_type"
                ),
                "otx_record": otx_record,
                "threat_points": (
                    threat_component["points"]
                ),
                "confidence_points": (
                    confidence_component["points"]
                ),
            }

    return selected

def score_article(
    article_id,
    include_otx=True,
):
    investigation = get_article_investigation(
        article_id,
        include_otx=include_otx,
    )

    if investigation is None:
        return None

    return build_article_scoring_report(
        investigation
    )