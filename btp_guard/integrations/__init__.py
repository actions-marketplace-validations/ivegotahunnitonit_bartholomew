"""
Bartholomew Trust Protocol (BTP v6.4.4) - Framework Integrations
================================================================
First-class adapters for LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex,
PydanticAI, Smolagents, OpenAI Swarm, MetaGPT, Dify, Qwen-Agent, ChatDev,
Haystack, CAMEL-AI, OpenDevin / OpenHands, Semantic Kernel, DSPy, Agno,
and Universal Coding Agents.
"""

from .crewai import BtpCrewAIGuard
from .langchain import BtpCallbackHandler, BtpToolGuard
from .swarm import BtpSwarmGuard
from .pydanticai import BtpPydanticAIGuard
from .smolagents import BtpSmolagentsGuard
from .langgraph import LangGraphBTPGuard, btp_langchain_tool
from .autogen import AutoGenBTPInterceptor, btp_autogen_guard
from .llamaindex import LlamaIndexBTPToolGuard, btp_llamaindex_tool
from .nvidia_nim import BartholomewNIMGuard

from .metagpt import BtpMetaGPTGuard
from .dify import BtpDifyGuard
from .qwen_agent import BtpQwenAgentGuard
from .chatdev import BtpChatDevGuard
from .haystack import BtpHaystackGuard
from .camel import BtpCamelGuard
from .opendevin import BtpOpenDevinGuard
from .semantic_kernel import BtpSemanticKernelGuard
from .dspy import BtpDSPyGuard
from .agno import BtpAgnoGuard
from .coding_agents import BtpCodingAgentGuard, wrap_coding_agent

from . import crewai
from . import langchain
from . import langgraph
from . import autogen
from . import llamaindex
from . import nvidia_nim
from . import pydanticai
from . import smolagents
from . import swarm
from . import metagpt
from . import dify
from . import qwen_agent
from . import chatdev
from . import haystack
from . import camel
from . import opendevin
from . import semantic_kernel
from . import dspy
from . import agno
from . import coding_agents

from .stripe_agent import BtpStripeAgentGuard, StripeSecurityVetoException, BtpStripeLicenseRequiredException, wrap_stripe
from . import stripe_agent

from .universal_pay import BtpUniversalPayGuard, PaymentProvider, UniversalSecurityVetoException, wrap_payment
from . import universal_pay

from .grok import BtpGrokGuard, GrokSecurityVetoException, wrap_grok
from . import grok

from .m2m_toll import BtpM2MMicroToll
from . import m2m_toll

from .generative_media import (
    BtpGenerativeMediaGuard,
    MediaProvider,
    GenerativeMediaSecurityVetoException,
    wrap_midjourney,
    wrap_suno,
    wrap_elevenlabs,
    wrap_runway,
)
from . import generative_media

from .google_genai import BtpGoogleGenAIGuard, wrap_google_genai_tool
from . import google_genai

__all__ = [
    "BtpStripeAgentGuard",
    "StripeSecurityVetoException",
    "stripe_agent",
    "BtpCrewAIGuard",
    "BtpCallbackHandler",
    "BtpToolGuard",
    "BtpSwarmGuard",
    "BtpPydanticAIGuard",
    "BtpSmolagentsGuard",
    "LangGraphBTPGuard",
    "btp_langchain_tool",
    "AutoGenBTPInterceptor",
    "btp_autogen_guard",
    "LlamaIndexBTPToolGuard",
    "BartholomewNIMGuard",
    "btp_llamaindex_tool",
    "BtpMetaGPTGuard",
    "BtpDifyGuard",
    "BtpQwenAgentGuard",
    "BtpChatDevGuard",
    "BtpHaystackGuard",
    "BtpCamelGuard",
    "BtpOpenDevinGuard",
    "BtpSemanticKernelGuard",
    "BtpDSPyGuard",
    "BtpAgnoGuard",
    "BtpCodingAgentGuard",
    "wrap_coding_agent",
    "crewai",
    "langchain",
    "langgraph",
    "autogen",
    "llamaindex",
    "nvidia_nim",
    "pydanticai",
    "smolagents",
    "swarm",
    "metagpt",
    "dify",
    "qwen_agent",
    "chatdev",
    "haystack",
    "camel",
    "opendevin",
    "semantic_kernel",
    "dspy",
    "agno",
    "coding_agents",
    "BtpUniversalPayGuard",
    "PaymentProvider",
    "UniversalSecurityVetoException",
    "wrap_payment",
    "BtpGrokGuard",
    "GrokSecurityVetoException",
    "BtpM2MMicroToll",
    "m2m_toll",
    "BtpGenerativeMediaGuard",
    "MediaProvider",
    "GenerativeMediaSecurityVetoException",
    "wrap_midjourney",
    "wrap_suno",
    "wrap_elevenlabs",
    "wrap_runway",
    "generative_media",
    "BtpGoogleGenAIGuard",
    "wrap_google_genai_tool",
    "google_genai",
]
