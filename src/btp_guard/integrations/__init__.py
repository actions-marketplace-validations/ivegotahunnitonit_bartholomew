"""
Bartholomew Trust Protocol (BTP v5.4.19) - Framework Integrations
================================================================
First-class adapters for LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex,
PydanticAI, Smolagents, and OpenAI Swarm.
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

from . import crewai
from . import langchain
from . import langgraph
from . import autogen
from . import llamaindex
from . import nvidia_nim
from . import pydanticai
from . import smolagents
from . import swarm

from .stripe_agent import BtpStripeAgentGuard, StripeSecurityVetoException, BtpStripeLicenseRequiredException, wrap_stripe
from . import stripe_agent

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
    "crewai",
    "langchain",
    "langgraph",
    "autogen",
    "llamaindex",
    "nvidia_nim",
    "pydanticai",
    "smolagents",
    "swarm",
]

from .universal_pay import BtpUniversalPayGuard, PaymentProvider, UniversalSecurityVetoException, wrap_payment
from . import universal_pay

from .grok import BtpGrokGuard, GrokSecurityVetoException, wrap_grok
from . import grok

from .m2m_toll import BtpM2MMicroToll
from . import m2m_toll
