import os
from urllib.parse import quote
import requests
from dotenv import load_dotenv

from database.otx_repository import save_otx_indicator
load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

OTX_TYPE_SLUGS = {
    "IPv4": "IPv4",
    "IPv6": "IPv6",
    "domain": "domain",
    "URL": "url",
    "FileHash-MD5": "file",
    "FileHash-SHA1": "file",
    "FileHash-SHA256": "file",
}



def get_otx_type_slug(indicator_type):
    try:
        return OTX_TYPE_SLUGS[indicator_type]

    except KeyError as error:
        raise ValueError(
            f"Unsupported OTX indicator type: {indicator_type}"
        ) from error


def fetch_otx_indicator(
    indicator: str,
    indicator_type: str,
):
    if not OTX_API_KEY:
        raise ValueError(
            "OTX_API_KEY was not found in the .env file"
        )

    otx_type_slug = get_otx_type_slug(
        indicator_type
    )

    encoded_indicator = (
        quote(indicator, safe="")
        if indicator_type == "URL"
        else indicator
    )

    url = (
        f"{OTX_BASE_URL}/indicators/"
        f"{otx_type_slug}/{encoded_indicator}/general"
    )

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=15,
    )

    response.raise_for_status()

    return response.json()

def normalize_otx_indicator(data,indicator,indicator_type):
    pulse_info=data.get("pulse_info",{})
    related=pulse_info.get("related",{})
    alienvault=related.get("alienvault",{})

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation":data.get("reputation"),
        "pulse_count":pulse_info.get("count",0),
        "country":data.get("country_name"),
        "country_code":data.get("country_code"),
        "asn":data.get("asn"),
        "malware_families":alienvault.get("malware_families",[],),
        "adversaries":alienvault.get("adversary",[],),
        "industries":alienvault.get("industries",[],),
        "validation":data.get("validation",[]),
        "sections":data.get("sections",[]),  
    }


def enrich_otx_indicator(indicator:str,indicator_type:str):
    raw_data=fetch_otx_indicator(indicator,indicator_type)
    normalized_data=normalize_otx_indicator(raw_data,indicator,indicator_type)
    save_otx_indicator(normalized_data)
    return normalized_data




if __name__ == "__main__":
    result = enrich_otx_indicator(
        "8.8.8.8",
        "IPv4",
    )

    print(result)