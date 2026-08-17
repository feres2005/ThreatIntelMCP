import requests
import logging



NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
logger=logging.getLogger(__name__)

def get_preffered_description(descriptions):
   if not isinstance(descriptions,list):
      return ""
   for description in descriptions:
      if not isinstance(description,dict):
         continue
      lang=description.get("lang")
      value=description.get("value")

      if lang=="en" and isinstance(value,str) and value:
         return value
   for description in descriptions:
      if not isinstance(description,dict):
         continue

      lang=description.get("lang")
      value=description.get("value")

      if lang=="fr" and isinstance(value,str)and value:
         return value
   
   for description in descriptions:
      if  not isinstance(description,dict):
         continue
      value=description.get("value")

      if isinstance(value,str) and value:
         return value
   
   return ""

def get_preffered_cvss_matrics(metrics):
    if not isinstance(metrics, dict):
        return None

    metric_keys = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_key in metric_keys:
        metric_entries = metrics.get(metric_key)

        if not isinstance(metric_entries, list) or not metric_entries:
            continue

        first_metric = metric_entries[0]

        if not isinstance(first_metric, dict):
            continue

        cvss_data = first_metric.get("cvssData")

        if isinstance(cvss_data, dict):
            return cvss_data

    return None


def get_reference_links(references):
   if not isinstance(references,list):
      return []
   
   links=[]

   for reference in references :
      if not isinstance(reference,dict):
         continue
      url =reference.get("url")

      if not isinstance(url,str) or not url:
         continue
      if url not in links:
         links.append(url)

   return links


def fetch_cve_from_nvd(cve_id):
    params = {
        "cveID": cve_id
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=10
        )
        response.raise_for_status()

    except requests.exceptions.RequestException as error:
        logger.error(
            "Failed to fetch CVE data from NVD for %s: %s",
            cve_id,
            error
        )
        return None

    try:
        return response.json()

    except requests.exceptions.JSONDecodeError as error:
        logger.error(
            "NVD returned invalid JSON for %s: %s",
            cve_id,
            error
        )
        return None

def normalize_cve_data(raw_data):
   if not isinstance(raw_data,dict):
      logger.warning("Invalid NVD response: expected a dictionary")
      return None
   vulnerabilities=raw_data.get("vulnerabilities")

   if not isinstance(vulnerabilities,list):
      logger.warning("invalid NVD response:vulnerabilities must be a list")
      return None
   
   if not vulnerabilities:
      logger.warning("No vulnerabilities found in NVD response")
      return None




   vulnerability = vulnerabilities[0]

   if not isinstance(vulnerability,dict):
      logger.warning(
         "Invalid NVD response: vulnerability entry must be a dictionary"
      )
      return None
   cve=vulnerability.get("cve")


   if not isinstance(cve,dict):
      logger.warning("Invalid NVD response: missing or invalid CVE object")
      return None
   
   cve_id=cve.get("id")
   if not isinstance(cve_id,str)or not cve_id:
      logger.warning("invalid nvd response:missing or invalid cve id")
      return None

   metrics = cve.get("metrics", {})
   cvss = get_preffered_cvss_matrics(metrics)
   return{
      "cve_id":cve_id,
      "description":get_preffered_description(cve.get("descriptions", [])),
      "published":cve.get("published"),
      "last_modified":cve.get("lastModified"),
      "cvss_score":cvss.get("baseScore")if cvss else None,
      "severity":cvss.get("baseSeverity")if cvss else None,
      "reference_links":get_reference_links(cve.get("references",[])),
   }


