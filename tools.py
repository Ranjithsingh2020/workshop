import requests
from langchain.tools import tool
import ipaddress
import os
import json
import ipaddress
from dotenv import load_dotenv

import shodan

load_dotenv()

BASE_URL = "https://cvedb.shodan.io"

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

####################################
# Shodan Client
####################################

api = shodan.Shodan(SHODAN_API_KEY)

####################################
# Helper
####################################

def is_ip(value: str):
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False

####################################
# Tool 1 - GET CVE INFORMATION
####################################

@tool
def get_cve_details(cve_id: str) -> str:
    """
    Get vulnerability information for a CVE ID.
    Example:
        CVE-2024-3400
        CVE-2023-3519
    """

    cve_id = cve_id.upper().strip()

    url = f"{BASE_URL}/cve/{cve_id}"

    response = requests.get(url, timeout=20)

    if response.status_code != 200:
        return f"Unable to find {cve_id}"

    data = response.json()

    output = f"""
CVE: {data.get("cve_id")}

Summary:
{data.get("summary")}

CVSS:
{data.get("cvss")}

EPSS:
{data.get("epss")}

Known Exploited (KEV):
{data.get("kev")}

Ransomware Campaign:
{data.get("ransomware_campaign")}

Published:
{data.get("published_time")}

References:
"""

    refs = data.get("references", [])

    for ref in refs[:10]:
        output += f"\n- {ref}"

    return output


####################################
# Tool 2 - GET IP/DOMAIN INFO
####################################

@tool
def shodan_lookup(target: str) -> str:
    """
    Lookup an IP address or domain using Shodan.

    Input:
        target = IP or domain

    Returns:
        JSON string containing host information.
    """

    try:

        if is_ip(target):

            result = api.host(target)

            data = {
                "ip": result.get("ip_str"),
                "organization": result.get("org"),
                "operating_system": result.get("os"),
                "country": result.get("country_name"),
                "city": result.get("city"),
                "ports": result.get("ports"),
                "hostnames": result.get("hostnames"),
                "vulns": list(result.get("vulns", {}).keys()),
                "isp": result.get("isp"),
                "asn": result.get("asn"),
                "tags": result.get("tags"),
            }

        else:

            result = api.dns.domain_info(target)

            data = result

        return json.dumps(data, indent=2)

    except Exception as e:
        return f"Error: {e}"

