import os
import requests
from scapy.all import rdpcap, Raw
from dotenv import load_dotenv
from langchain.tools import tool
from langchain.agents import create_agent
from langchain.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import AzureChatOpenAI


### Load environment variables #####

load_dotenv()
os.environ["LANGCHAIN_TRACING_V2"] = "true"

# -----------------------------------
# Extract IPs
# -----------------------------------
def extract_ips_from_pcap(pcap_file: str):
    packets = rdpcap(pcap_file)
    ips = set()
    domains = set()

    for pkt in packets:
        if pkt.haslayer("IP"):
            ips.add(pkt["IP"].src)
            ips.add(pkt["IP"].dst)

    return list(ips)


# -----------------------------------
# OTX Tool
# -----------------------------------
@tool
def otx_ip_lookup(ip: str) -> str:
    """Query AlienVault OTX for IP threat intelligence"""
    api_key = os.getenv("OTX_API_KEY")

    base_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(f"{base_url}/general", headers=headers, timeout=10)
        data = response.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("count", 0)
        reputation = data.get("reputation", 0)

        pulse_names = [p.get("name") for p in pulse_info.get("pulses", [])[:5]]

        if pulses > 5 or reputation < 0:
            verdict = "Malicious"
        elif pulses > 0:
            verdict = "Suspicious"
        else:
            verdict = "Benign"

        return (
            f"IP: {ip}\n"
            f"Pulses: {pulses}\n"
            f"Reputation: {reputation}\n"
            f"Threats: {pulse_names}\n"
            f"Verdict: {verdict}"
        )

    except Exception as e:
        return f"Error: {str(e)}"

#################################################
## TOOL DEFINITION - SNORT RULE CREATION
#################################################

@tool
def generate_snort_rule(input_data: str) -> str:
    """
    Generate Snort rule based on IP and severity.
    Input format: "IP:1.2.3.4, Verdict:Malicious"
    """
    try:
        parts = dict(x.split(":") for x in input_data.split(", "))
        ip = parts.get("IP")
        verdict = parts.get("Verdict", "Unknown")

        if verdict == "Malicious":
            priority = 1
            action = "drop"

        elif verdict == "Suspicious":
            priority = 2
            action = "alert"

        else:
            return f"No rule generated for benign IP {ip}"

        rule = (
            f'{action} ip any any -> {ip} any '
            f'(msg:"{verdict} IP detected {ip}"; '
            f'priority:{priority}; sid:1000001; rev:1;)'
        )

        return rule

    except Exception as e:
        return f"Error generating rule: {str(e)}"
# -----------------------------------
# Build Agent
# -----------------------------------
def build_agent():
    llm = AzureChatOpenAI(
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
        temperature=0
    )
    
    tools = [
        otx_ip_lookup,
        generate_snort_rule
    ]
    
    agent = create_agent(
    model=llm,
    tools=tools)

    return agent


# -----------------------------------
# Analysis Function
# -----------------------------------
def analyze_pcap_with_agent(pcap_file: str):

    agent = build_agent()
    ips = extract_ips_from_pcap(pcap_file)

    results = []

    for ip in ips:
        response = agent.invoke({
        "messages": [
            SystemMessage(content=""" You are a cybersecurity analyst.
                    Step 1: Use OTX tool to analyze the IP.
                    Step 2: If the IP is malicious or suspicious, 
                    generate a Snort rule using the rule generator tool. 
                    If the Verdict for IP is Malicious, it should be dropped using snort 
                    If its Verdict for IP is Suspicious, it should be monitored using alert
                    If the IP is Benign,then no snort rule required for same. 
                    Step 3: Return both analysis and rule."""),
            HumanMessage(content=f"Analyze IP: {ip}")
            ]
            })

        # Extract final answer
        final_output = response["messages"][-1].content

        results.append({
            "ip": ip,
            "analysis": final_output
        })

    return results
