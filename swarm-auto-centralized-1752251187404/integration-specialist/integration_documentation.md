# API Key Storage Integration Documentation

## Overview

This integration module system provides a secure and flexible framework for managing API keys and authentication across multiple services. The system includes:

1. **Base Integration Module** - Core functionality for all integrations
2. **Service-Specific Integrations** - Pre-built integrations for GitHub, Claude, and other services
3. **Generic Integration Module** - Flexible integration for any API service
4. **Configuration Management** - Centralized configuration and profile management
5. **Integration Testing** - Comprehensive testing utilities

## Quick Start

### Basic Usage

```python
from base_integration import SecureKeyWrapper
from github_integration import create_github_integration
from claude_integration import create_claude_integration

# Create wrapper
wrapper = SecureKeyWrapper()

# Register integrations
github = create_github_integration()
claude = create_claude_integration()

wrapper.register_integration(github)
wrapper.register_integration(claude)

# Store API keys
wrapper.set_key('github', 'your-github-token')
wrapper.set_key('claude', 'sk-ant-your-claude-key')

# Use integrations
user_info = github.get_user_info()
response = claude.create_message(
    messages=[{'role': 'user', 'content': 'Hello!'}],
    model='claude-3-haiku-20240307'
)
```

## Module Details

### 1. Base Integration Module (`base_integration.py`)

The foundation for all service integrations, providing:

- **Abstract base class** with common functionality
- **Secure key storage** interface
- **Configuration management**
- **Service registration**

Key Classes:
- `BaseIntegration`: Abstract base class for all integrations
- `SecureKeyWrapper`: Central manager for all service integrations

### 2. GitHub Integration (`github_integration.py`)

Pre-configured integration for GitHub API:

```python
from github_integration import GitHubIntegration

# Create integration
github = GitHubIntegration()

# Configure required scopes
github.configure_scopes(['repo', 'user', 'workflow'])

# Use the integration
repos = github.list_repos()
rate_limit = github.get_rate_limit()
user_info = github.get_user_info()

# Create a new repository
new_repo = github.create_repo(
    name='my-new-repo',
    description='Created via API',
    private=True
)
```

### 3. Claude Integration (`claude_integration.py`)

Pre-configured integration for Claude/Anthropic API:

```python
from claude_integration import ClaudeIntegration

# Create integration
claude = ClaudeIntegration()

# Configure models
claude.configure_model_preferences([
    'claude-3-sonnet-20240229',
    'claude-3-opus-20240229',
    'claude-3-haiku-20240307'
])

# Create prompt templates
claude.create_prompt_template(
    'code_review',
    'Review this {language} code:\n```{language}\n{code}\n```',
    ['language', 'code']
)

# Use the template
prompt = claude.use_prompt_template(
    'code_review',
    language='python',
    code='def hello(): print("Hello")'
)

# Send message
response = claude.create_message(
    messages=[{'role': 'user', 'content': prompt}],
    model='claude-3-sonnet-20240229'
)
```

### 4. Generic Integration (`generic_integration.py`)

Flexible integration for any API service:

```python
from generic_integration import GenericServiceIntegration, create_custom_integration

# Create custom integration
custom_api = create_custom_integration(
    service_name='MyAPI',
    base_url='https://api.myservice.com',
    auth_type='header',        # 'header', 'query', or 'basic'
    auth_field='X-API-Key',
    auth_prefix='',             # No prefix
    validation_pattern=r'^[A-Z0-9]{32}$',
    test_path='/v1/status'
)

# Make requests
response = custom_api.get('https://api.myservice.com/v1/data')
response = custom_api.post(
    'https://api.myservice.com/v1/resource',
    json={'name': 'test'}
)
```

Pre-configured integrations available:
- OpenAI
- Slack
- Stripe
- SendGrid

### 5. Configuration Management (`config_manager.py`)

Centralized configuration and profile management:

```python
from config_manager import ConfigurationManager, ServiceProfile

# Create manager
config_manager = ConfigurationManager()

# Register service
config_manager.register_service('myservice', {
    'api_base_url': 'https://api.myservice.com',
    'timeout': 30,
    'retry_attempts': 3
})

# Create profiles
profile = ServiceProfile('myservice', config_manager)
profile.create_profile('development', {
    'api_base_url': 'https://dev-api.myservice.com',
    'debug': True
})
profile.create_profile('production', {
    'api_base_url': 'https://api.myservice.com',
    'debug': False
})

# Switch profiles
profile.set_active_profile('development')

# Export/Import configurations
config_export = config_manager.export_config('myservice', format='yaml')
config_manager.import_config(config_export, 'myservice', format='yaml')

# Generate environment variables template
env_template = config_manager.create_environment_template(['github', 'claude'])
```

### 6. Integration Testing (`integration_tests.py`)

Comprehensive testing framework:

```python
from integration_tests import IntegrationTestRunner, IntegrationTestSuite
from base_integration import SecureKeyWrapper

# Create wrapper with integrations
wrapper = SecureKeyWrapper()
# ... register integrations ...

# Run all tests
runner = IntegrationTestRunner(wrapper)
runner.save_all_reports('test_reports')

# Run individual integration test
github_suite = IntegrationTestSuite(github_integration)
report = github_suite.run_all_tests()
github_suite.print_summary()
github_suite.save_report('github_test_report.json')
```

## Security Best Practices

1. **Never hardcode API keys** in your code
2. **Use environment variables** for production deployments
3. **Implement proper key rotation** policies
4. **Use service-specific profiles** for different environments
5. **Enable audit logging** for key access
6. **Validate API keys** before storing
7. **Test connections** before saving configurations

## Environment Variables

The system supports environment variables for API keys:

```bash
# GitHub
export GITHUB_API_KEY='your-github-token'

# Claude
export CLAUDE_API_KEY='sk-ant-your-claude-key'

# Custom service
export MYSERVICE_API_KEY='your-api-key'
```

## Advanced Usage

### Custom Authentication Methods

```python
class MyCustomIntegration(BaseIntegration):
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        # Custom authentication logic
        return {
            'X-Custom-Auth': f'Custom {api_key}',
            'X-Request-ID': str(uuid.uuid4())
        }
```

### Rate Limiting

```python
from integration_tests import test_rate_limiting

# Test rate limiting behavior
results = test_rate_limiting(
    integration=github,
    requests_per_second=10
)

print(f"Successful: {results['successful_requests']}")
print(f"Rate limited: {results['rate_limited_requests']}")
```

### Batch Operations

```python
# Register multiple integrations at once
integrations = [
    create_github_integration(),
    create_claude_integration(),
    create_openai_integration(),
    create_slack_integration()
]

for integration in integrations:
    wrapper.register_integration(integration)

# Get all service info
all_services = wrapper.list_services()
```

## Error Handling

The system provides comprehensive error handling:

```python
try:
    # Set invalid key
    success = wrapper.set_key('github', 'invalid-key')
    if not success:
        print("Invalid API key format or connection failed")
        
except ValueError as e:
    print(f"Configuration error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Extending the System

To add a new service integration:

1. Create a new integration class inheriting from `BaseIntegration`
2. Implement required abstract methods
3. Add service-specific methods
4. Create a factory function
5. Add to the test suite

Example:

```python
from base_integration import BaseIntegration

class MyServiceIntegration(BaseIntegration):
    def __init__(self):
        super().__init__('MyService')
        
    def validate_api_key(self, api_key: str) -> bool:
        # Implementation
        pass
        
    def test_connection(self, api_key: str) -> bool:
        # Implementation
        pass
        
    def _build_auth_headers(self, api_key: str) -> Dict[str, str]:
        # Implementation
        pass

def create_myservice_integration():
    return MyServiceIntegration()
```

## Troubleshooting

### Common Issues

1. **API Key Not Found**
   - Check environment variables
   - Verify key was stored successfully
   - Check service name spelling

2. **Connection Failed**
   - Verify API key is valid
   - Check network connectivity
   - Review service status

3. **Configuration Not Saved**
   - Check file permissions
   - Verify config directory exists
   - Check disk space

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Support

For issues or questions:
1. Check the test reports for detailed error information
2. Review service-specific documentation
3. Enable debug logging for more details
4. Verify API key permissions and scopes