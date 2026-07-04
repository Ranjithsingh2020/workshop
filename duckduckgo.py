import streamlit as st
import tempfile
import pandas as pd
import os
from langchain_openai import AzureChatOpenAI
from langchain_community.tools import DuckDuckGoSearchRun
from agent import analyze_pcap_with_agent

from dotenv import load_dotenv
import os

load_dotenv()



from langchain_community.tools import DuckDuckGoSearchRun
search = DuckDuckGoSearchRun()

# Run query
result = search.run("latest CVE vulnerabilities of 2026")

print(result)

