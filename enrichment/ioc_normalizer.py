import ipaddress
import re
from urllib.parse import urlparse


def normalize_ioc_text(value):
  if not isinstance(value,str):
    return None

  normalized_value=value.strip()

  if not normalized_value:
    return None

  normalized_value = normalized_value.replace("[.]",".")
  lowercase_value=normalized_value.lower()

  if lowercase_value.startswith("hxxps://"):
    normalized_value="https://"+normalized_value[8:]
  elif lowercase_value.startswith("hxxp://"):
    normalized_value = "http://" + normalized_value[7:]

  return normalized_value

HASH_TYPES={
  32:"FileHash-MD5",
  40:"FileHash-SHA1",
  64:"FileHash-SHA256"
}

def detect_ioc_type(value):
  normalized_value=normalize_ioc_text(value)

  if normalized_value is None:
    return None

  try:
    ip_address=ipaddress.ip_address(normalized_value)
    if ip_address.version==4:
      return "IPv4"

    return "IPv6"

  except ValueError:
    pass

  if re.fullmatch(r"[0-9a-fA-F]+",normalized_value):
    return HASH_TYPES.get(len(normalized_value))

  parsed_url=urlparse(normalized_value)
  if parsed_url.scheme.lower() in {"http","https"}:
    try:
      parsed_url.port
    except ValueError:
      return None
    hostname=parsed_url.hostname

    if hostname is None:
      return None

    try:
      ipaddress.ip_address(hostname)
      return "URL"

    except ValueError:
      if is_valid_domain(hostname):
        return "URL"

    return None

  if is_valid_domain(normalized_value):
    return "domain"

  return None

def is_valid_domain(value):
  domain = value.rstrip(".").lower()

  if len(domain)>253 or "." not in domain:
    return False

  labels=domain.split(".")

  for label in labels:
    if not 1 <= len(label) <= 63:
      return False

    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",label,):
      return False

  top_level_domain=labels[-1]

  if len(top_level_domain)<2:
    return False

  if top_level_domain.isdigit():
    return False

  return True

def normalize_ioc(value):
  normalized_value=normalize_ioc_text(value)
  indicator_type=detect_ioc_type(normalized_value)

  if indicator_type is None:
    return None

  if indicator_type in {"IPv4","IPv6"}:
    normalized_value=str(ipaddress.ip_address(normalized_value))

  elif indicator_type.startswith("FileHash-"):
    normalized_value=normalized_value.lower()

  elif indicator_type=="domain":
    normalized_value=normalized_value.rstrip(".").lower()

  return {
    "indicator":normalized_value,
    "indicator_type":indicator_type,
  }


def normalize_ioc_list(values):
  if not isinstance(values,list):
    raise ValueError("IOC values must be provided as a list.")

  normalized_iocs=[]
  seen_iocs=set()

  for value in values:
    normalized_ioc=normalize_ioc(value)

    if normalized_ioc is None:
      continue

    ioc_key=(
      normalized_ioc["indicator"],
      normalized_ioc["indicator_type"],
    )

    if ioc_key in seen_iocs:
      continue

    seen_iocs.add(ioc_key)
    normalized_iocs.append(normalized_ioc)

  return normalized_iocs