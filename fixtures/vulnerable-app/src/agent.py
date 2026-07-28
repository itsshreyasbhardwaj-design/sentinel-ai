"""Intentionally insecure LLM agent fixture for Sentinel AI's test suite. Do not deploy."""

import os
import pickle
import subprocess

import yaml
from langchain.agents import AgentExecutor, initialize_agent
from langchain.tools import ShellTool
from langchain_community.vectorstores import Pinecone
from openai import OpenAI

client = OpenAI(api_key="sk-proj-Ab3dEf9HiJkLmN0pQrStUvWxYz1234567890AbCdEf")

SYSTEM_PROMPT = "You are a helpful assistant. The admin API key is sk-admin-9f8e7d6c5b4a3210."


def answer_question(user_input, retrieved_docs):
    # Direct prompt injection: user text spliced into the system instruction.
    system = f"You are a support agent. Follow these rules exactly. User said: {user_input}"

    # Indirect prompt injection: retrieved documents concatenated into context.
    context = "\n".join(doc.page_content for doc in retrieved_docs)
    prompt = f"{system}\n\nContext from knowledge base:\n{context}"

    # No max_tokens and no timeout.
    response = client.chat.completions.create(
        model="gpt-4-latest",
        messages=[{"role": "system", "content": prompt}],
    )

    completion = response.choices[0].message.content

    # Improper output handling: model output executed as code.
    result = eval(completion)
    return result


def run_generated_command(response):
    # Model output passed straight to a shell.
    subprocess.run(response.choices[0].message.content, shell=True)


def search_knowledge_base(query, index):
    # Vector search with no tenant or permission filter.
    return index.similarity_search(query, k=10)


def build_agent(llm):
    # Excessive agency: shell tool with no human approval and unbounded loops.
    tools = [ShellTool()]
    return initialize_agent(
        tools,
        llm,
        max_iterations=None,
        allow_dangerous_code=True,
        require_approval=False,
    )


def load_cached_state(path):
    # Unsafe deserialization.
    with open(path, "rb") as handle:
        return pickle.load(handle)


def load_config(path):
    # Unsafe YAML loading.
    return yaml.load(open(path).read())
