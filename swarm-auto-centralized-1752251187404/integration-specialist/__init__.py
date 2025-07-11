"""
API Key Storage Integration Package
Provides secure integration modules for various API services
"""

# Base modules
from .base_integration import BaseIntegration, SecureKeyWrapper

# Service integrations
from .github_integration import GitHubIntegration, create_github_integration
from .claude_integration import ClaudeIntegration, create_claude_integration
from .generic_integration import (
    GenericServiceIntegration,
    create_openai_integration,
    create_slack_integration,
    create_stripe_integration,
    create_sendgrid_integration,
    create_custom_integration
)

# Configuration management
from .config_manager import (
    ConfigurationManager,
    ServiceProfile,
    create_default_configurations,
    SERVICE_TEMPLATES
)

# Testing utilities
from .integration_tests import (
    IntegrationTestSuite,
    IntegrationTestRunner,
    TestStatus,
    TestResult,
    test_api_key_storage,
    test_rate_limiting
)

# Version info
__version__ = '1.0.0'
__author__ = 'Integration Specialist Agent'

# Convenience function to create and configure all integrations
def create_all_integrations():
    """Create and return a wrapper with all pre-configured integrations"""
    wrapper = SecureKeyWrapper()
    
    # Register all available integrations
    integrations = [
        create_github_integration(),
        create_claude_integration(),
        create_openai_integration(),
        create_slack_integration(),
        create_stripe_integration(),
        create_sendgrid_integration()
    ]
    
    for integration in integrations:
        wrapper.register_integration(integration)
    
    return wrapper


# Quick setup function
def quick_setup(service_configs=None):
    """
    Quick setup for common use case
    
    Args:
        service_configs: Dict mapping service names to API keys
                        e.g., {'github': 'token', 'claude': 'key'}
    
    Returns:
        Configured SecureKeyWrapper instance
    """
    # Create wrapper with all integrations
    wrapper = create_all_integrations()
    
    # Create default configurations
    config_manager = create_default_configurations()
    
    # Set API keys if provided
    if service_configs:
        for service, api_key in service_configs.items():
            wrapper.set_key(service, api_key)
    
    return wrapper, config_manager


__all__ = [
    # Base classes
    'BaseIntegration',
    'SecureKeyWrapper',
    
    # Service integrations
    'GitHubIntegration',
    'ClaudeIntegration',
    'GenericServiceIntegration',
    
    # Factory functions
    'create_github_integration',
    'create_claude_integration',
    'create_openai_integration',
    'create_slack_integration',
    'create_stripe_integration',
    'create_sendgrid_integration',
    'create_custom_integration',
    
    # Configuration
    'ConfigurationManager',
    'ServiceProfile',
    'create_default_configurations',
    
    # Testing
    'IntegrationTestSuite',
    'IntegrationTestRunner',
    'TestStatus',
    'TestResult',
    
    # Utilities
    'create_all_integrations',
    'quick_setup',
    
    # Constants
    'SERVICE_TEMPLATES',
    '__version__'
]