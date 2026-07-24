from enrichment.cve_enricher import (
    fetch_cve_from_nvd,
    normalize_cve_data
)

from database.database import save_cve_enrichment

cve_data = fetch_cve_from_nvd("CVE-2021-44228")

if cve_data:
    normalized_cve = normalize_cve_data(cve_data)

    if normalized_cve:
        save_cve_enrichment(normalized_cve)
        print("CVE enrichment saved successfully.")