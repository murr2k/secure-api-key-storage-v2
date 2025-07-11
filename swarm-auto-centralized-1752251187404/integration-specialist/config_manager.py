"""
Service Configuration Management Module
Handles configuration for all API integrations
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """Manages configurations for all service integrations"""
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else self._get_default_config_dir()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.global_config_file = self.config_dir / 'global_config.json'
        self._load_global_config()
    
    def _get_default_config_dir(self) -> Path:
        """Get default configuration directory"""
        return Path.home() / '.api_key_storage' / 'configs'
    
    def _load_global_config(self) -> None:
        """Load global configuration"""
        if self.global_config_file.exists():
            try:
                with open(self.global_config_file, 'r') as f:
                    self.global_config = json.load(f)
            except Exception as e:
                logger.error(f"Error loading global config: {e}")
                self.global_config = {}
        else:
            self.global_config = {
                'created_at': datetime.now().isoformat(),
                'version': '1.0.0',
                'services': {}
            }
            self._save_global_config()
    
    def _save_global_config(self) -> None:
        """Save global configuration"""
        try:
            with open(self.global_config_file, 'w') as f:
                json.dump(self.global_config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving global config: {e}")
    
    def register_service(self, service_name: str, config: Dict[str, Any]) -> None:
        """Register a new service configuration"""
        self.global_config['services'][service_name] = {
            'registered_at': datetime.now().isoformat(),
            'config_file': f"{service_name.lower()}_config.json",
            'enabled': True,
            **config
        }
        self._save_global_config()
        
        # Create service-specific config file
        service_config_file = self.config_dir / f"{service_name.lower()}_config.json"
        if not service_config_file.exists():
            self.save_service_config(service_name, config)
    
    def get_service_config(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific service"""
        service_config_file = self.config_dir / f"{service_name.lower()}_config.json"
        if service_config_file.exists():
            try:
                with open(service_config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config for {service_name}: {e}")
        return None
    
    def save_service_config(self, service_name: str, config: Dict[str, Any]) -> None:
        """Save configuration for a specific service"""
        service_config_file = self.config_dir / f"{service_name.lower()}_config.json"
        try:
            with open(service_config_file, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuration saved for {service_name}")
        except Exception as e:
            logger.error(f"Error saving config for {service_name}: {e}")
    
    def update_service_config(self, service_name: str, updates: Dict[str, Any]) -> None:
        """Update specific configuration values for a service"""
        config = self.get_service_config(service_name) or {}
        config.update(updates)
        self.save_service_config(service_name, config)
    
    def enable_service(self, service_name: str) -> None:
        """Enable a service"""
        if service_name in self.global_config['services']:
            self.global_config['services'][service_name]['enabled'] = True
            self._save_global_config()
    
    def disable_service(self, service_name: str) -> None:
        """Disable a service"""
        if service_name in self.global_config['services']:
            self.global_config['services'][service_name]['enabled'] = False
            self._save_global_config()
    
    def is_service_enabled(self, service_name: str) -> bool:
        """Check if a service is enabled"""
        service = self.global_config['services'].get(service_name, {})
        return service.get('enabled', False)
    
    def list_services(self) -> List[Dict[str, Any]]:
        """List all registered services"""
        services = []
        for name, info in self.global_config['services'].items():
            services.append({
                'name': name,
                'enabled': info.get('enabled', False),
                'registered_at': info.get('registered_at'),
                'config_file': info.get('config_file')
            })
        return services
    
    def export_config(self, service_name: Optional[str] = None, format: str = 'json') -> str:
        """Export configuration to string"""
        if service_name:
            config = self.get_service_config(service_name)
            if not config:
                raise ValueError(f"No configuration found for {service_name}")
        else:
            config = self.global_config
        
        if format == 'json':
            return json.dumps(config, indent=2)
        elif format == 'yaml':
            return yaml.dump(config, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def import_config(self, config_str: str, service_name: Optional[str] = None, 
                     format: str = 'json') -> None:
        """Import configuration from string"""
        if format == 'json':
            config = json.loads(config_str)
        elif format == 'yaml':
            config = yaml.safe_load(config_str)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if service_name:
            self.save_service_config(service_name, config)
        else:
            # Import as global config
            self.global_config.update(config)
            self._save_global_config()
    
    def create_environment_template(self, services: Optional[List[str]] = None) -> str:
        """Create environment variable template for services"""
        template_lines = ["# API Key Storage Environment Variables\n"]
        
        if services is None:
            services = list(self.global_config['services'].keys())
        
        for service in services:
            template_lines.append(f"# {service}")
            template_lines.append(f"export {service.upper()}_API_KEY='your_{service.lower()}_api_key_here'")
            
            # Add service-specific environment variables
            config = self.get_service_config(service)
            if config:
                for key, value in config.items():
                    if key not in ['api_key', 'created_at', 'updated_at']:
                        env_var = f"{service.upper()}_{key.upper()}"
                        template_lines.append(f"export {env_var}='{value}'")
            
            template_lines.append("")
        
        return '\n'.join(template_lines)


class ServiceProfile:
    """Manages service-specific profiles and environments"""
    
    def __init__(self, service_name: str, config_manager: ConfigurationManager):
        self.service_name = service_name
        self.config_manager = config_manager
        self.profiles_dir = config_manager.config_dir / 'profiles' / service_name.lower()
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
    
    def create_profile(self, profile_name: str, config: Dict[str, Any]) -> None:
        """Create a new profile for the service"""
        profile_file = self.profiles_dir / f"{profile_name}.json"
        config['profile_name'] = profile_name
        config['created_at'] = datetime.now().isoformat()
        
        with open(profile_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Profile '{profile_name}' created for {self.service_name}")
    
    def get_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific profile"""
        profile_file = self.profiles_dir / f"{profile_name}.json"
        if profile_file.exists():
            with open(profile_file, 'r') as f:
                return json.load(f)
        return None
    
    def list_profiles(self) -> List[str]:
        """List all profiles for the service"""
        return [f.stem for f in self.profiles_dir.glob('*.json')]
    
    def set_active_profile(self, profile_name: str) -> None:
        """Set the active profile for the service"""
        profile = self.get_profile(profile_name)
        if not profile:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        # Update service config with profile settings
        self.config_manager.update_service_config(
            self.service_name,
            {'active_profile': profile_name, **profile}
        )
    
    def get_active_profile(self) -> Optional[str]:
        """Get the currently active profile"""
        config = self.config_manager.get_service_config(self.service_name)
        return config.get('active_profile') if config else None


# Configuration templates for common services
SERVICE_TEMPLATES = {
    'github': {
        'api_base_url': 'https://api.github.com',
        'required_scopes': ['repo', 'user'],
        'rate_limit_strategy': 'exponential_backoff',
        'timeout': 30,
        'retry_attempts': 3
    },
    'claude': {
        'api_base_url': 'https://api.anthropic.com/v1',
        'api_version': '2023-06-01',
        'default_model': 'claude-3-sonnet-20240229',
        'max_tokens_default': 1000,
        'temperature_default': 0.0
    },
    'openai': {
        'api_base_url': 'https://api.openai.com/v1',
        'default_model': 'gpt-4-turbo-preview',
        'organization_id': '',
        'timeout': 60
    },
    'aws': {
        'region': 'us-east-1',
        'service': 's3',
        'signature_version': 'v4',
        'addressing_style': 'auto'
    }
}


def create_default_configurations():
    """Create default configurations for common services"""
    config_manager = ConfigurationManager()
    
    for service_name, template in SERVICE_TEMPLATES.items():
        if service_name not in config_manager.global_config['services']:
            config_manager.register_service(service_name, template)
            logger.info(f"Created default configuration for {service_name}")
    
    return config_manager


# Example usage
def configuration_example():
    """Example of using configuration management"""
    # Create configuration manager
    config_manager = create_default_configurations()
    
    # List all services
    services = config_manager.list_services()
    print("Registered services:")
    for service in services:
        print(f"- {service['name']} ({'enabled' if service['enabled'] else 'disabled'})")
    
    # Create profiles for GitHub
    github_profile = ServiceProfile('github', config_manager)
    
    # Create development profile
    github_profile.create_profile('development', {
        'api_base_url': 'https://api.github.com',
        'timeout': 60,
        'rate_limit_strategy': 'aggressive'
    })
    
    # Create production profile
    github_profile.create_profile('production', {
        'api_base_url': 'https://api.github.com',
        'timeout': 30,
        'rate_limit_strategy': 'conservative',
        'retry_attempts': 5
    })
    
    # Set active profile
    github_profile.set_active_profile('development')
    
    # Export configuration
    config_export = config_manager.export_config('github', format='yaml')
    print(f"\nGitHub configuration:\n{config_export}")
    
    # Create environment template
    env_template = config_manager.create_environment_template(['github', 'claude'])
    print(f"\nEnvironment template:\n{env_template}")
    
    return config_manager