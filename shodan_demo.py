import os
from dotenv import load_dotenv

from langchain.agents import create_agent
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

from tools import get_cve_details, shodan_lookup

load_dotenv()

os.environ["LANGSMITH_TRACING"] = "true"

# Hugging Face model
llm = ChatHuggingFace(
    llm=HuggingFaceEndpoint(
        repo_id="Qwen/Qwen2.5-72B-Instruct",
        task="text-generation",
        max_new_tokens=1024,
        temperature=0.2,
    )
)

agent = create_agent(
    model=llm,
    tools=[get_cve_details, shodan_lookup],
    system_prompt="""
You are a cybersecurity assistant.

Whenever the user asks about a CVE, use the get_cve_details tool.

Whenever the user asks about an IP address or domain,
use the shodan_lookup tool.

Summarize the output from the tool calls in a readable way.

If user asks any other questions outside this topic, respond that user is only allowed to 
ask questions in this specific topic.
"""
)

while True:
    query = input("\nUser: ")

    if query.lower() == "exit":
        break

    response = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": query
                }
            ]
        }
    )

    # Print only the final AI message
    print("\nAssistant:\n")
    print(response["messages"][-1].content)