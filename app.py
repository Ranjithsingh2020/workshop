import streamlit as st
import tempfile
import pandas as pd

from agent import analyze_pcap_with_agent

st.set_page_config(page_title="IP Reputation Analyzer", layout="wide")

st.title(" @ PCAP IP Reputation Analyzer (OTX + Azure OpenAI) @")

uploaded_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])


if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(uploaded_file.read())
        temp_path = tmp_file.name

    st.success("PCAP uploaded successfully")

    if st.button("Analyze"):
        with st.spinner("Analyzing traffic..."):
            results = analyze_pcap_with_agent(temp_path)

        # Convert to DataFrame
        df = pd.DataFrame(results)

        st.subheader(" $ Analysis Results $")
        st.dataframe(df, use_container_width=True)

        # Expandable detailed view
        st.subheader(" $ Detailed Analysis $")

        for r in results:
            with st.expander(f"IP: {r['ip']}"):
                st.text(r["analysis"])
