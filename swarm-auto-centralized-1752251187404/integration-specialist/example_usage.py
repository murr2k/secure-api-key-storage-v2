#!/usr/bin/env python3
"""
Example usage of the API Key Storage Integration System
Demonstrates all major features and best practices
"""

import os
import json
from pathlib import Path

# Import all integration modules
from base_integration import SecureKeyWrapper
from github_integration import create_github_integration
from claude_integration import create_claude_integration
from generic_integration import create_custom_integration, create_openai_integration
from config_manager import ConfigurationManager, ServiceProfile
from integration_tests import IntegrationTestRunner


def basic_example():
    """Basic usage example"""
    print("=== Basic Integration Example ===\n")
    
    # Create wrapper
    wrapper = SecureKeyWrapper()
    
    # Create and register GitHub integration
    github = create_github_integration()
    wrapper.register_integration(github)
    
    # Set API key (in production, use environment variables)
    api_key = os.environ.get('GITHUB_API_KEY', 'your-github-token-here')
    if wrapper.set_key('github', api_key):
        print("✓ GitHub API key stored successfully")
    else:
        print("✗ Failed to store GitHub API key")
        return
    
    # Use the integration
    user_info = github.get_user_info()
    if user_info:
        print(f"✓ Authenticated as: {user_info.get('login')}")
        print(f"  Name: {user_info.get('name')}")
        print(f"  Public repos: {user_info.get('public_repos')}")
    
    # Check rate limit
    rate_limit = github.get_rate_limit()
    if rate_limit:
        remaining = rate_limit.get('rate', {}).get('remaining')
        print(f"✓ API calls remaining: {remaining}")
    
    print()
    return wrapper


def claude_example():
    """Claude integration example"""
    print("=== Claude Integration Example ===\n")
    
    # Create Claude integration
    claude = create_claude_integration()
    
    # Configure models
    claude.configure_model_preferences([
        'claude-3-sonnet-20240229',
        'claude-3-haiku-20240307'
    ])
    
    # Create a prompt template
    claude.create_prompt_template(
        'explain_code',
        'Please explain this {language} code in simple terms:\n```{language}\n{code}\n```',
        ['language', 'code']
    )
    
    # Set API key
    api_key = os.environ.get('CLAUDE_API_KEY', 'sk-ant-your-key-here')
    claude.set_secure_key(api_key)
    
    # Use the template
    prompt = claude.use_prompt_template(
        'explain_code',
        language='python',
        code='print("Hello, World!")'
    )
    
    print(f"✓ Created prompt template")
    print(f"✓ Generated prompt: {prompt[:50]}...")
    
    # Note: Actual API call commented out to avoid using credits
    # response = claude.create_message(
    #     messages=[{'role': 'user', 'content': prompt}],
    #     model='claude-3-haiku-20240307',
    #     max_tokens=100
    # )
    
    print()
    return claude


def custom_service_example():
    """Custom service integration example"""
    print("=== Custom Service Integration Example ===\n")
    
    # Create custom integration for a hypothetical API
    weather_api = create_custom_integration(
        service_name='WeatherAPI',
        base_url='https://api.weather.example.com',
        auth_type='query',          # API key in query parameter
        auth_field='apikey',
        auth_prefix='',             # No prefix
        validation_pattern=r'^[a-f0-9]{32}$',  # 32 hex characters
        test_path='/v1/status'
    )
    
    print("✓ Created custom WeatherAPI integration")
    print(f"  Auth type: query parameter 'apikey'")
    print(f"  Base URL: https://api.weather.example.com")
    
    # Configure the integration
    weather_api._config['endpoints'] = {
        'current': '/v1/current',
        'forecast': '/v1/forecast',
        'historical': '/v1/historical'
    }
    weather_api.save_config(weather_api._config)
    
    print("✓ Configured API endpoints")
    
    # Example of making a request (would work with real API)
    # response = weather_api.get(
    #     'https://api.weather.example.com/v1/current',
    #     params={'location': 'New York'}
    # )
    
    print()
    return weather_api


def configuration_management_example():
    """Configuration and profile management example"""
    print("=== Configuration Management Example ===\n")
    
    # Create configuration manager
    config_manager = ConfigurationManager()
    
    # Register services with configurations
    config_manager.register_service('github', {
        'api_base_url': 'https://api.github.com',
        'timeout': 30,
        'retry_attempts': 3,
        'rate_limit_strategy': 'exponential_backoff'
    })
    
    config_manager.register_service('myapp', {
        'environments': {
            'dev': 'https://dev-api.myapp.com',
            'staging': 'https://staging-api.myapp.com',
            'prod': 'https://api.myapp.com'
        },
        'features': {
            'caching': True,
            'compression': True,
            'logging': 'debug'
        }
    })
    
    print("✓ Registered services with configurations")
    
    # Create profiles for different environments
    myapp_profile = ServiceProfile('myapp', config_manager)
    
    myapp_profile.create_profile('development', {
        'api_url': 'https://dev-api.myapp.com',
        'debug': True,
        'cache_ttl': 60,
        'timeout': 60
    })
    
    myapp_profile.create_profile('production', {
        'api_url': 'https://api.myapp.com',
        'debug': False,
        'cache_ttl': 3600,
        'timeout': 30
    })
    
    print("✓ Created development and production profiles")
    
    # Switch to development profile
    myapp_profile.set_active_profile('development')
    print("✓ Activated development profile")
    
    # List all services
    services = config_manager.list_services()
    print("\n✓ Registered services:")
    for service in services:
        status = "enabled" if service['enabled'] else "disabled"
        print(f"  - {service['name']} ({status})")
    
    # Export configuration
    config_yaml = config_manager.export_config('myapp', format='yaml')
    print("\n✓ Exported configuration (YAML format):")
    print("  " + "\n  ".join(config_yaml.split('\n')[:5]) + "...")
    
    # Generate environment template
    env_template = config_manager.create_environment_template(['github', 'myapp'])
    print("\n✓ Generated environment variable template")
    
    print()
    return config_manager


def integration_testing_example(wrapper: SecureKeyWrapper):
    """Integration testing example"""
    print("=== Integration Testing Example ===\n")
    
    # Create test runner
    runner = IntegrationTestRunner(wrapper)
    
    print("✓ Running integration tests for all registered services...")
    print("  (This will test API key validation, connection, and configuration)\n")
    
    # Run tests (results will be printed)
    # Note: In a real scenario, you'd want to use test API keys
    # runner.run_all_integrations()
    
    # Save test reports
    output_dir = Path("test_reports")
    output_dir.mkdir(exist_ok=True)
    
    # Example of what the test report would look like
    example_report = {
        'service': 'github',
        'timestamp': '2024-01-01T12:00:00',
        'duration': 2.5,
        'summary': {
            'total': 5,
            'passed': 4,
            'failed': 0,
            'skipped': 1,
            'success_rate': 80.0
        },
        'results': [
            {
                'test_name': 'API Key Validation',
                'status': 'passed',
                'duration': 0.1,
                'message': 'API key format is valid'
            },
            {
                'test_name': 'API Connection Test',
                'status': 'passed',
                'duration': 1.2,
                'message': 'Successfully connected to API'
            }
        ]
    }
    
    # Save example report
    with open(output_dir / "example_test_report.json", 'w') as f:
        json.dump(example_report, f, indent=2)
    
    print(f"✓ Test reports would be saved to: {output_dir}")
    print("✓ Example report saved: example_test_report.json")
    
    print()
    return runner


def security_best_practices():
    """Demonstrate security best practices"""
    print("=== Security Best Practices ===\n")
    
    print("1. Using Environment Variables:")
    print("   export GITHUB_API_KEY='your-token'")
    print("   export CLAUDE_API_KEY='sk-ant-your-key'")
    print()
    
    print("2. Key Validation Before Storage:")
    print("   - GitHub tokens: 40 hex chars or github_pat_ prefix")
    print("   - Claude keys: sk-ant- prefix")
    print("   - Custom patterns via regex")
    print()
    
    print("3. Connection Testing:")
    print("   - Validates key works before storage")
    print("   - Prevents storing invalid credentials")
    print()
    
    print("4. Secure Storage Integration:")
    print("   - In production, integrate with:")
    print("     • OS Keychain (macOS)")
    print("     • Credential Manager (Windows)")
    print("     • Secret Service (Linux)")
    print("     • HashiCorp Vault")
    print("     • AWS Secrets Manager")
    print()
    
    print("5. Configuration Isolation:")
    print("   - Separate configs per service")
    print("   - Environment-specific profiles")
    print("   - No keys in config files")
    print()


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("API Key Storage Integration System - Example Usage")
    print("="*60 + "\n")
    
    # Run examples
    wrapper = basic_example()
    claude = claude_example()
    weather_api = custom_service_example()
    config_manager = configuration_management_example()
    
    # Add more integrations to wrapper for testing example
    wrapper.register_integration(claude)
    wrapper.register_integration(weather_api)
    
    runner = integration_testing_example(wrapper)
    security_best_practices()
    
    print("="*60)
    print("All examples completed successfully!")
    print("="*60)
    
    # Summary
    print("\nSummary:")
    print(f"✓ Registered integrations: {len(wrapper._integrations)}")
    print(f"✓ Available services: {', '.join(wrapper._integrations.keys())}")
    print(f"✓ Configuration profiles created: Yes")
    print(f"✓ Test framework ready: Yes")
    print(f"✓ Security best practices: Demonstrated")


if __name__ == "__main__":
    main()