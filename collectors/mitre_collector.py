import requests
from database.mitre_repository import save_mitre_technique

MITRE_DATASETS = {
    "enterprise-attack": (
        "https://raw.githubusercontent.com/"
        "mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    ),
    "mobile-attack": (
        "https://raw.githubusercontent.com/"
        "mitre-attack/attack-stix-data/master/"
        "mobile-attack/mobile-attack.json"
    ),
    "ics-attack": (
        "https://raw.githubusercontent.com/"
        "mitre-attack/attack-stix-data/master/"
        "ics-attack/ics-attack.json"
    ),
}


def fetch_mitre_dataset(domain):
  url=MITRE_DATASETS.get(domain)
  if url is None:
    raise ValueError(f"unsupported  MITRE domain: {domain}")
  
  response= requests.get(url,timeout=60)
  response.raise_for_status()

  return response.json()

def extract_mitre_external_id(external_references):
   
   for reference in external_references:
      if reference.get("source_name")=="mitre-attack":
         return reference.get("external_id")
   return None


def normalize_mitre_technique(mitre_object,domain):
   external_references=mitre_object.get("external_references",[])
   technique_id=extract_mitre_external_id(external_references)

   if technique_id is None:
      return None

   return {
      
      "stix_id":mitre_object.get("id"),
      "technique_id":technique_id,
      "domain":domain,
      "name":mitre_object.get("name"),
      "description":mitre_object.get("description"),
      "is_subtechnique":mitre_object.get("x_mitre_is_subtechnique",False),
      "platforms": mitre_object.get("x_mitre_platforms", []),
      "kill_chain_phases": mitre_object.get("kill_chain_phases",[]),
      "version":mitre_object.get("x_mitre_version"),
      "reference_links":external_references,
      "created":mitre_object.get("created"),
      "modified":mitre_object.get("modified"),
      "revoked":mitre_object.get("revoked",False),
      "deprecated":mitre_object.get("x_mitre_deprecated",False),

   }

def collect_mitre_techniques(domain):
   dataset = fetch_mitre_dataset(domain)
   saved_count=0

   for mitre_object in dataset.get("objects",[]):
      if mitre_object.get("type") !="attack-pattern":
         continue
      technique=normalize_mitre_technique(mitre_object,domain)
      if technique is None:
         continue
      save_mitre_technique(technique)
      saved_count +=1
   return saved_count

if __name__ == "__main__":

    for domain in MITRE_DATASETS:
        saved_count = collect_mitre_techniques(domain)

        print(
            f"{domain}: {saved_count} techniques saved."
        )