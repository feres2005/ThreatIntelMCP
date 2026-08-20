import logging
import re
import json
import os
from dotenv import load_dotenv
from anthropic import Anthropic

load_dotenv()
logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

client = Anthropic(api_key=ANTHROPIC_API_KEY) 

MAX_RETRIES=2


STRING_LIST_FIELDS = [
    "classification",
    "iocs",
    "cves",
    "malware",
    "mitre_techniques",
    "apt_groups",
    "targeted_sectors",
    "affected_technologies",
]

EXPECTED_FIELD_TYPES = {
    "summary": str,
    "classification": list,
    "severity": str,
    "confidence_score": (int, float),
    "iocs": list,
    "cves": list,
    "malware": list,
    "mitre_techniques": list,
    "apt_groups": list,
    "targeted_sectors": list,
    "affected_technologies": list,
}



REQUIRED_FIELDS = [
    "summary",
    "classification",
    "severity",
    "confidence_score",
    "iocs",
    "cves",
    "malware",
    "mitre_techniques",
    "apt_groups",
    "targeted_sectors",
    "affected_technologies"
]

ALLOWED_CLASSIFICATIONS=[

  "vulnerability",
  "zero-day",
  "malware",
  "ransomware",
  "APT",
  "phishing",
  "botnet",
  "spyware",
  "trojan",
  "worm",
  "information-stealer",
  "cryptominer",
  "web-skimmer",
  "credential-theft",
  "supply-chain",
  "DDoS",
  "cloud-attack",
  "mobile-malware",
  "data-breach",
  "intrusion",
  "ICS-attack",
]

ALLOWED_SEVERITIES=[
  "Critical",
  "High",
  "Medium",
  "Low",
  "None"
]




def get_missing_fields(analysis_data):
  missing_fields=[]
  for field in REQUIRED_FIELDS:
    if field not in analysis_data:
      missing_fields.append(field)
  return missing_fields

def get_type_errors(analysis_data):
  type_errors={}

  for field,expected_type in EXPECTED_FIELD_TYPES.items():
    value=analysis_data[field]
    if not isinstance(value,expected_type):
      if isinstance(expected_type,tuple):
        expected_name =" or ".join(
          expected.__name__ for expected in expected_type
        )
      else:
        expected_name=expected_type.__name__
      type_errors[field]={
        "expected" :expected_name,
        "actual":type(value).__name__
      }
  return type_errors

def get_list_item_type_errors(analysis_data):
  item_type_errors ={}

  for field in STRING_LIST_FIELDS:
    invalid_items=[]
    for index,value in enumerate(analysis_data[field]):
      if not isinstance(value,str):
        invalid_items.append({
          "index":index,
          "value":value,
          "actual_type":type(value).__name__
        })
    if invalid_items:
      item_type_errors[field]={
        "expected_item_type":"str",
        "invalid_items":invalid_items
      }
  return item_type_errors


#validation helpers 

def get_invalid_classifications(classifications):
  invalid_classifications=[]

  for classification in classifications:
    if classification not in ALLOWED_CLASSIFICATIONS:
      invalid_classifications.append(classification)
  return invalid_classifications


def get_invalid_severity(severity):
  if severity  not in ALLOWED_SEVERITIES:
    return severity
  return None

def get_invalid_confidence_score(confidence_score):
  if isinstance(confidence_score,bool):
    return confidence_score
  if not isinstance(confidence_score,(int,float)):
    return confidence_score
  if confidence_score<0.0 or confidence_score>1.0:
    return confidence_score
  return None

def get_invalid_cves(cves):
  invalid_cves=[]
  for cve in cves:
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}",cve):
      invalid_cves.append(cve)
      
  return invalid_cves

def get_invalid_mitre_techniques(mitre_techniques):
  invalid_mitre_techniques = []
  for technique in mitre_techniques:
    if not  re.fullmatch(r"T\d{4}(\.\d{3})?",technique):
      invalid_mitre_techniques.append(technique)
  return invalid_mitre_techniques

#returning the validation errors

def get_validation_errors(analysis_data):
  validation_errors={}
  missing_fields=get_missing_fields(analysis_data)
  if missing_fields:
    validation_errors["missing_fields"]=missing_fields
    return validation_errors
  
  type_errors = get_type_errors(analysis_data)

  if type_errors:
    validation_errors["type_errors"]=type_errors
    return validation_errors

  item_type_errors=get_list_item_type_errors(analysis_data)
  if item_type_errors:
    validation_errors["item_type_errors"] = item_type_errors
    return validation_errors


  errors={}
  missing_fields=get_missing_fields(analysis_data)
  if missing_fields:
    errors["missing_fields"]=missing_fields
  invalid_classifications=get_invalid_classifications(
    analysis_data.get("classification",[])
  )
  invalid_severity=get_invalid_severity(
    analysis_data.get("severity","")
  )
  invalid_cves= get_invalid_cves(analysis_data.get('cves',[]))
  invalid_confidence_score=get_invalid_confidence_score(analysis_data.get("confidence_score",None))
  invalid_mitre_techniques=get_invalid_mitre_techniques(analysis_data.get("mitre_techniques",[]))
  if invalid_classifications:
    errors["invalid_classifications"]=invalid_classifications

  if invalid_severity:
    errors["invalid_severity"]=invalid_severity
  
  if invalid_confidence_score is not None:
    errors["invalid_confidence_score"]=invalid_confidence_score

  if invalid_cves:
    errors["invalid_cves"]=invalid_cves
  
  if invalid_mitre_techniques:
    errors["invalid_mitre_techniques"]=invalid_mitre_techniques
  return errors


# Apply safe fallback values when Claude cannot fully correct the analysis.
def apply_python_defaults(analysis_data,validation_errors):
  if "invalid_severity" in validation_errors:
    analysis_data["severity"]="None"

  if "invalid_confidence_score" in validation_errors:
    analysis_data["confidence_score"]=0.0

  if "invalid_classifications" in validation_errors:
    invalid_classifications=validation_errors["invalid_classifications"]
    analysis_data["classification"]=[
      classification for classification in analysis_data["classification"]
      if classification not in invalid_classifications
    ]

  if "invalid_cves" in validation_errors:
    invalid_cves=validation_errors["invalid_cves"]
    analysis_data["cves"]=[
      cve for cve in analysis_data["cves"]
      if cve not in invalid_cves
    ]

  if "invalid_mitre_techniques" in validation_errors:
    invalid_mitre_techniques=validation_errors["invalid_mitre_techniques"]
    analysis_data["mitre_techniques"]=[
      technique for technique  in analysis_data["mitre_techniques"]
      if technique not in invalid_mitre_techniques
    ]
  if "missing_fields" in validation_errors:
    for field in validation_errors["missing_fields"]:
      if field in["classification","iocs","cves","malware","mitre_techniques","apt_groups","targeted_sectors","affected_technologies"]:
        analysis_data[field]=[]
      elif field=="severity":
        analysis_data[field]="None"
      elif field=="confidence_score":
        analysis_data[field]=0.0
      elif field == "summary":
        analysis_data[field]=""

  return analysis_data



def parse_analysis_json(raw_text):
  cleaned_text=clean_json_response(raw_text)
  return json.loads(cleaned_text)

def try_parse_analysis_json(raw_text):
  try:
    return parse_analysis_json(raw_text)
  except json.JSONDecodeError:
    logger.error("claude returned invalid JSON")
    logger.debug("Raw Claude response: %s", raw_text)
    return None
def try_parse_and_validate_analysis(raw_text):
  analysis_data=try_parse_analysis_json(raw_text)
  if analysis_data is None :
    return None,{
      "invalid_json": "Claude response could not be parsed as JSON"
    }

  if not isinstance(analysis_data,dict):
    logger.error(
      "Claude returned a valid JSON value, but the root type was %s instead of an object",
      type(analysis_data).__name__
    )
    return analysis_data,{
      "invalid_root_type":type(analysis_data).__name__
    }
  validation_errors= get_validation_errors(analysis_data)
  return analysis_data,validation_errors



def clean_json_response(claude_text):
  # Remove Markdown code fences before JSON parsing. 
  cleaned_text=claude_text.replace("```json", "")
  cleaned_text=cleaned_text.replace("```", "")
  return cleaned_text.strip()    

def extract_claude_text(response):
  if not response.content:
    logger.error("claude returned an empty response")
    return None
  first_block=response.content[0]
  if first_block.type != "text":
    logger.error("Claude returned an unexpected content block type: %s",first_block.type)
    return None
  return first_block.text

  
def analyze_article(article):
  try:

    prompt = build_analysis_prompt(article)
    response=client.messages.create(
      model="claude-haiku-4-5-20251001",
      max_tokens=500,
      messages=[
        {
          "role":"user",
          "content":prompt
        }
      ]
    )
  except Exception as error:
    logger.error("Claude API error during initial analysis: %s",error)
    return None

  claude_text=extract_claude_text(response)
  if claude_text is None:
    return None
  
  #calling the helper function to check if claude returned the correct json
  analysis_data,validation_errors=try_parse_and_validate_analysis(claude_text)


  
  retry_count=0

  while validation_errors and retry_count< MAX_RETRIES:
    #we are trying to make claude genrate another response incase the first reponse had an issue
    logger.warning("validation errors :%s",validation_errors)
    corrected_text=regenerate_analysis(claude_text,validation_errors)
    if corrected_text is None:
      retry_count+=1
      continue

    new_analysis_data, new_validation_errors = (
      try_parse_and_validate_analysis(corrected_text)
      )

    claude_text = corrected_text
    analysis_data = new_analysis_data
    validation_errors = new_validation_errors

    retry_count += 1
  
  if validation_errors:
    logger.warning(
        "Validation errors remain after retries: %s",
        validation_errors
    )

    unsafe_errors = {
        "invalid_json",
        "invalid_root_type",
        "type_errors",
        "item_type_errors"
    }

    if any(error in validation_errors for error in unsafe_errors):
        logger.error(
            "Claude did not return a structurally valid analysis "
            "after %s correction attempts",
            MAX_RETRIES
        )
        return None

    analysis_data = apply_python_defaults(
        analysis_data,
        validation_errors
    )

  #since the article id is not part of the json returned by claude, i added it manually
  analysis_data["article_id"]=article.id
  return analysis_data
  
  
def build_correction_prompt(original_response,validation_errors):

  #in case there is an invalid JSON in the cluade response we add this new prompt to correct claude

  prompt=f"""
  you previously returned this JSON:
  {original_response}
  this JSON has these validation errors:
  {json.dumps(validation_errors,indent=2)}
  fix only the invalid or missing parts .
  keep all correct fields unchanged .

  return ONLY valid raw JSON.
  do not use Markdown
  do not use code fences.
  your response must start with {{ and end with}}.
  """
  return prompt


def regenerate_analysis(original_response,validation_errors):
  try:
    prompt=build_correction_prompt(original_response,validation_errors)
    response = client.messages.create(
      model="claude-haiku-4-5-20251001",
      max_tokens=500,
      messages=[
        {
          "role":"user",
          "content":prompt
        }
      ]
    )
  except Exception as error:
    logger.error("Claude API error during correction: %s",error)
    return None
  
  corrected_text=extract_claude_text(response)
  if corrected_text is None:
    return None
  return corrected_text

def build_analysis_prompt(article):

  allowed_classifications = ', '.join(ALLOWED_CLASSIFICATIONS)
  prompt = f"""


  You are a cybersecurity SOC analyst specialized in Threat Intelligence.

  Analyze the following cybersecurity article and extract the threat intelligence.

  Title:
  {article.title}

  Summary:
  {article.summary}

  Return ONLY a valid JSON object.

  Do not include:
  - Markdown
  - Code blocks
  - Explanations
  - Extra text

  The JSON must have exactly the following structure:

  {{

    "summary": "",
    "classification": [],
    "severity": "",
    "confidence_score": 0.0,
    "iocs": [],
    "cves": [],
    "malware": [],
    "mitre_techniques": [],
    "apt_groups": [],
    "targeted_sectors": [],
    "affected_technologies": []
  }}

    Rules:

  General evidence rules:
  - Use only information explicitly supported by the provided title and summary.
  - Do not invent, assume, or infer named entities, indicators, or attributions that are not supported by the text.
  - The article may be technology or security news without describing a cyber threat.
  - A service outage, product update, watermarking feature, support notice, or performance problem is not a cyberattack unless the text explicitly provides evidence of malicious activity.
  - A data breach is not automatically information-stealer malware. Use "information-stealer" only when the text describes malware or a malicious tool designed to steal information.

  Field rules:
  - summary: provide one concise factual summary based only on the supplied text.
  - classification: choose one or more values ONLY from the following list:
  {allowed_classifications}
  - Do not invent new classifications, use synonyms, or return values outside this list.
  - Return an empty classification list when no supported cyber-threat category is present.
  - Use "data-breach" only when unauthorized access, disclosure, exposure, or theft of data is explicitly described.
  - Use "intrusion" only when successful unauthorized access to a system or network is explicitly described and no more precise category fully   the incident.
  - Use "ICS-attack" only when the supplied text explicitly describes malicious activity affecting industrial control systems, operational technology, industrial equipment, or a physical industrial process.
  - Use "APT" only when the text explicitly describes an advanced persistent threat, a state-sponsored or state-linked actor, or a named actor conducting cyber espionage.
  - A named ransomware gang, cybercriminal group, malware operation, or generic threat actor is not automatically an APT.
  - severity: use "Critical", "High", "Medium", "Low", or "None".
  - Use "None" when no supported malicious cyber activity or exploitable vulnerability is described.
  - Do not assign threat severity to a normal service outage or benign technology article.
  - confidence_score: return a decimal number between 0.0 and 1.0 representing how strongly the supplied text supports the extracted fields.
  - confidence_score measures the strength of the supplied cyber-threat evidence, not confidence that the JSON format is correct.
  - When classification is [] and severity is "None" because no threat evidence exists, return 0.0.
  - Use 0.9 or above only when concrete evidence such as an explicit CVE, named threat actor, named malware, literal IOC, or clearly described malicious behavior is present.
  - Use 0.5 or below when the text is incomplete, ambiguous, or does not provide concrete threat evidence.
  - iocs: return only literal IPv4 addresses, IPv6 addresses, domains, URLs, MD5 hashes, SHA-1 hashes, or SHA-256 hashes that appear in the supplied text.
  - Do not treat product names, package names, package versions, CVE IDs, malware names, filenames, general words, or inferred infrastructure as IOCs.
  - cves: return only literal CVE identifiers present in the supplied text.
  - malware: return only explicitly named malware families or software that the supplied text explicitly identifies as malicious.
  - Do not classify legitimate or dual-use tools as malware solely because attackers abused them. When appropriate, place those tools in affected_technologies instead.
  - Do not place generic descriptions such as "malware", "infostealer", "backdoor", "trojan", or "ransomware" in the malware list unless the text clearly presents them as a formal proper name.
  - A programming language or platform followed by a generic malware category, such as "Rust infostealer" or "Linux malware", is not a malware-family name unless the text explicitly presents it as one.
  - When two names are explicitly presented as aliases for the same malware, return only the primary name used by the article.
  - mitre_techniques: return a MITRE ATT&CK technique ID only when the supplied text describes a concrete observable behavior that directly and unambiguously matches the technique definition.
  - Generic statements such as "a vulnerability was exploited", "data was stolen", "a backdoor was deployed", "C2 was used", or "a system was breached" are not sufficient by themselves to assign a specific technique.
  - Do not assign T1190 unless exploitation of a public-facing or internet-facing application or service is explicitly supported.
  - Do not assign T1005 merely because data was stolen; collection from a local system, local files, or an equivalent local source must be explicitly supported.
  - Do not assign T1053 unless a scheduled task, scheduled job, cron job, or equivalent scheduling mechanism is explicitly described.
  - Do not assign T1199 merely because attackers used an existing, private, or third-party network; abuse of a trusted relationship must be explicitly described.
  - Do not assign a phishing technique unless phishing behavior is explicitly described.
  - For ICS techniques, the specific control-system behavior or operational impact required by the technique must be explicitly described.
  - When more than one technique could fit, return only techniques directly supported by the supplied text. When uncertain, omit the technique.
  - apt_groups: return only explicitly named groups that the supplied text identifies as APT, state-sponsored, state-linked, or cyber-espionage actors.
  - Do not place ordinary ransomware gangs, cybercriminal groups, malware operations, generic attacker descriptions, or unnamed state-nexus actors in apt_groups.
  - targeted_sectors: return only industries or sectors explicitly identified as targets or victims.
  - affected_technologies: return only software, hardware, vendors, or technologies explicitly described as affected.
  - If evidence for a list field is absent, return [].

  Return raw JSON only.
  Your response must start with {{ and end with }}.
  Do not wrap the JSON in ```json or ``` code fences
  Return raw JSON only. No Markdown. No code fences.
  """
  return prompt

