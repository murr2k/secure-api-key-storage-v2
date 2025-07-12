"""
Service integrations for Secure API Key Storage
"""

from .base_integration import BaseIntegration, SecureKeyWrapper
from .github_integration import GitHubIntegration
from .claude_integration import ClaudeIntegration
from .generic_integration import GenericServiceIntegration as GenericIntegration

__all__ = [
    "BaseIntegration",
    "SecureKeyWrapper",
    "GitHubIntegration",
    "ClaudeIntegration",
    "GenericIntegration",
]
