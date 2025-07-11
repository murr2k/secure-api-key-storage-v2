"""
Monitoring and Alerting Configuration for Secure API Key Storage

This module provides configuration and setup for monitoring security events,
audit integrity, and key rotation compliance.
"""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import yaml
import json


class AlertChannel(Enum):
    """Alert notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SMS = "sms"


@dataclass
class AlertRule:
    """Alert rule configuration"""
    name: str
    condition: str
    threshold: float
    duration: str
    severity: str
    channels: List[AlertChannel]
    description: str
    metadata: Dict[str, Any] = None


class MonitoringConfiguration:
    """Configuration for monitoring and alerting"""
    
    def __init__(self):
        self.prometheus_config = self._generate_prometheus_config()
        self.alert_rules = self._generate_alert_rules()
        self.grafana_dashboards = self._generate_grafana_dashboards()
    
    def _generate_prometheus_config(self) -> Dict[str, Any]:
        """Generate Prometheus configuration"""
        return {
            "global": {
                "scrape_interval": "15s",
                "evaluation_interval": "15s"
            },
            "scrape_configs": [
                {
                    "job_name": "secure_key_storage",
                    "static_configs": [
                        {
                            "targets": ["localhost:9090"]
                        }
                    ],
                    "metrics_path": "/metrics"
                }
            ],
            "rule_files": [
                "alerts/security_alerts.yml",
                "alerts/rotation_alerts.yml",
                "alerts/audit_alerts.yml"
            ]
        }
    
    def _generate_alert_rules(self) -> List[AlertRule]:
        """Generate alert rules for various security events"""
        return [
            # Authentication failures
            AlertRule(
                name="HighAuthFailureRate",
                condition='rate(audit_events_total{event_type="auth_failure"}[5m]) > 0.5',
                threshold=0.5,
                duration="5m",
                severity="warning",
                channels=[AlertChannel.SLACK, AlertChannel.EMAIL],
                description="High rate of authentication failures detected"
            ),
            
            AlertRule(
                name="SuspiciousAuthPattern",
                condition='rate(audit_events_total{event_type="auth_failure"}[1m]) > 10',
                threshold=10,
                duration="1m",
                severity="critical",
                channels=[AlertChannel.PAGERDUTY, AlertChannel.SMS],
                description="Possible brute force attack detected"
            ),
            
            # Tampering detection
            AlertRule(
                name="AuditLogTampering",
                condition='audit_signatures_verified{result="failure"} > 0',
                threshold=0,
                duration="1m",
                severity="critical",
                channels=[AlertChannel.PAGERDUTY, AlertChannel.EMAIL, AlertChannel.SMS],
                description="Audit log tampering detected - immediate investigation required"
            ),
            
            # Key rotation compliance
            AlertRule(
                name="KeyRotationOverdue",
                condition='rotation_enforcement_actions{action_type="key_blocked"} > 0',
                threshold=0,
                duration="5m",
                severity="warning",
                channels=[AlertChannel.EMAIL, AlertChannel.SLACK],
                description="API keys blocked due to rotation policy violations"
            ),
            
            AlertRule(
                name="ManyKeysNearExpiry",
                condition='count(rotation_due < time() + 7*24*60*60) > 5',
                threshold=5,
                duration="1h",
                severity="info",
                channels=[AlertChannel.EMAIL],
                description="Multiple keys approaching rotation deadline"
            ),
            
            # Security events
            AlertRule(
                name="PolicyViolations",
                condition='rate(audit_events_total{event_type="policy_violation"}[15m]) > 0.1',
                threshold=0.1,
                duration="15m",
                severity="warning",
                channels=[AlertChannel.SLACK],
                description="Elevated rate of policy violations"
            ),
            
            AlertRule(
                name="CriticalSecurityEvent",
                condition='audit_events_total{severity="critical"} > 0',
                threshold=0,
                duration="1m",
                severity="critical",
                channels=[AlertChannel.PAGERDUTY, AlertChannel.SMS, AlertChannel.EMAIL],
                description="Critical security event detected"
            ),
            
            # Access patterns
            AlertRule(
                name="UnusualAccessPattern",
                condition='rate(audit_events_total{event_type="key_accessed"}[1m]) > 100',
                threshold=100,
                duration="2m",
                severity="warning",
                channels=[AlertChannel.SLACK],
                description="Unusually high key access rate detected"
            ),
            
            AlertRule(
                name="AccessFromNewLocation",
                condition='count(distinct(ip_address)) by (user_id) > 3',
                threshold=3,
                duration="1h",
                severity="info",
                channels=[AlertChannel.EMAIL],
                description="User accessing from multiple IP addresses"
            )
        ]
    
    def _generate_grafana_dashboards(self) -> Dict[str, Any]:
        """Generate Grafana dashboard configurations"""
        return {
            "security_overview": {
                "title": "Security Overview Dashboard",
                "panels": [
                    {
                        "title": "Authentication Events",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": 'rate(audit_events_total{event_type="auth_success"}[5m])',
                                "legendFormat": "Successful Authentications"
                            },
                            {
                                "expr": 'rate(audit_events_total{event_type="auth_failure"}[5m])',
                                "legendFormat": "Failed Authentications"
                            }
                        ]
                    },
                    {
                        "title": "Key Access Patterns",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": 'rate(audit_events_total{event_type="key_accessed"}[5m])',
                                "legendFormat": "Key Access Rate"
                            }
                        ]
                    },
                    {
                        "title": "Security Alerts",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": 'sum(security_alerts_total)',
                                "legendFormat": "Total Security Alerts"
                            }
                        ]
                    },
                    {
                        "title": "Audit Log Integrity",
                        "type": "gauge",
                        "targets": [
                            {
                                "expr": 'audit_signatures_verified{result="success"} / sum(audit_signatures_verified)',
                                "legendFormat": "Integrity Score"
                            }
                        ]
                    }
                ]
            },
            "rotation_compliance": {
                "title": "Key Rotation Compliance Dashboard",
                "panels": [
                    {
                        "title": "Keys by Age",
                        "type": "piechart",
                        "targets": [
                            {
                                "expr": 'count(key_age_days < 30)',
                                "legendFormat": "< 30 days"
                            },
                            {
                                "expr": 'count(key_age_days >= 30 and key_age_days < 60)',
                                "legendFormat": "30-60 days"
                            },
                            {
                                "expr": 'count(key_age_days >= 60 and key_age_days < 90)',
                                "legendFormat": "60-90 days"
                            },
                            {
                                "expr": 'count(key_age_days >= 90)',
                                "legendFormat": "> 90 days"
                            }
                        ]
                    },
                    {
                        "title": "Rotation Actions",
                        "type": "bar",
                        "targets": [
                            {
                                "expr": 'sum(rotation_enforcement_actions) by (action_type)',
                                "legendFormat": "{{action_type}}"
                            }
                        ]
                    },
                    {
                        "title": "Blocked Keys",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": 'count(key_status{status="blocked"})',
                                "legendFormat": "Blocked Keys"
                            }
                        ]
                    }
                ]
            },
            "audit_analytics": {
                "title": "Audit Analytics Dashboard",
                "panels": [
                    {
                        "title": "Event Volume by Type",
                        "type": "heatmap",
                        "targets": [
                            {
                                "expr": 'sum(audit_events_total) by (event_type)',
                                "legendFormat": "{{event_type}}"
                            }
                        ]
                    },
                    {
                        "title": "Top Users by Activity",
                        "type": "table",
                        "targets": [
                            {
                                "expr": 'topk(10, sum(audit_events_total) by (user_id))',
                                "format": "table"
                            }
                        ]
                    },
                    {
                        "title": "Critical Events Timeline",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": 'audit_events_total{severity=~"error|critical"}',
                                "legendFormat": "{{severity}} - {{event_type}}"
                            }
                        ]
                    }
                ]
            }
        }
    
    def generate_prometheus_alerts_yaml(self) -> str:
        """Generate Prometheus alerts configuration in YAML format"""
        alerts_config = {
            "groups": []
        }
        
        # Group alerts by category
        security_alerts = []
        rotation_alerts = []
        audit_alerts = []
        
        for rule in self.alert_rules:
            alert_def = {
                "alert": rule.name,
                "expr": rule.condition,
                "for": rule.duration,
                "labels": {
                    "severity": rule.severity
                },
                "annotations": {
                    "summary": rule.description,
                    "description": f"{{ $labels.instance }} - {rule.description}"
                }
            }
            
            if "auth" in rule.name.lower() or "security" in rule.name.lower():
                security_alerts.append(alert_def)
            elif "rotation" in rule.name.lower():
                rotation_alerts.append(alert_def)
            else:
                audit_alerts.append(alert_def)
        
        if security_alerts:
            alerts_config["groups"].append({
                "name": "security_alerts",
                "interval": "30s",
                "rules": security_alerts
            })
        
        if rotation_alerts:
            alerts_config["groups"].append({
                "name": "rotation_alerts",
                "interval": "60s",
                "rules": rotation_alerts
            })
        
        if audit_alerts:
            alerts_config["groups"].append({
                "name": "audit_alerts",
                "interval": "30s",
                "rules": audit_alerts
            })
        
        return yaml.dump(alerts_config, default_flow_style=False)
    
    def generate_alertmanager_config(self) -> Dict[str, Any]:
        """Generate Alertmanager configuration"""
        return {
            "global": {
                "resolve_timeout": "5m"
            },
            "route": {
                "group_by": ["alertname", "severity"],
                "group_wait": "10s",
                "group_interval": "10s",
                "repeat_interval": "1h",
                "receiver": "default",
                "routes": [
                    {
                        "match": {"severity": "critical"},
                        "receiver": "critical_alerts",
                        "continue": True
                    },
                    {
                        "match": {"severity": "warning"},
                        "receiver": "warning_alerts"
                    },
                    {
                        "match": {"severity": "info"},
                        "receiver": "info_alerts"
                    }
                ]
            },
            "receivers": [
                {
                    "name": "default",
                    "email_configs": [
                        {
                            "to": "security-team@example.com",
                            "from": "alerts@example.com",
                            "smarthost": "smtp.example.com:587",
                            "auth_username": "alerts@example.com",
                            "auth_password": "password",
                            "headers": {
                                "Subject": "Security Alert: {{ .GroupLabels.alertname }}"
                            }
                        }
                    ]
                },
                {
                    "name": "critical_alerts",
                    "pagerduty_configs": [
                        {
                            "service_key": "your-pagerduty-service-key",
                            "description": "{{ .GroupLabels.alertname }}: {{ .Annotations.summary }}"
                        }
                    ],
                    "slack_configs": [
                        {
                            "api_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                            "channel": "#security-critical",
                            "title": "🚨 Critical Security Alert",
                            "text": "{{ .Annotations.description }}"
                        }
                    ]
                },
                {
                    "name": "warning_alerts",
                    "slack_configs": [
                        {
                            "api_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                            "channel": "#security-warnings",
                            "title": "⚠️ Security Warning",
                            "text": "{{ .Annotations.description }}"
                        }
                    ]
                },
                {
                    "name": "info_alerts",
                    "email_configs": [
                        {
                            "to": "security-notifications@example.com",
                            "from": "alerts@example.com",
                            "headers": {
                                "Subject": "Security Info: {{ .GroupLabels.alertname }}"
                            }
                        }
                    ]
                }
            ]
        }
    
    def save_configurations(self, output_dir: str = "./monitoring"):
        """Save all monitoring configurations to files"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save Prometheus config
        with open(os.path.join(output_dir, "prometheus.yml"), 'w') as f:
            yaml.dump(self.prometheus_config, f, default_flow_style=False)
        
        # Save alert rules
        alerts_dir = os.path.join(output_dir, "alerts")
        os.makedirs(alerts_dir, exist_ok=True)
        
        with open(os.path.join(alerts_dir, "security_alerts.yml"), 'w') as f:
            f.write(self.generate_prometheus_alerts_yaml())
        
        # Save Alertmanager config
        with open(os.path.join(output_dir, "alertmanager.yml"), 'w') as f:
            yaml.dump(self.generate_alertmanager_config(), f, default_flow_style=False)
        
        # Save Grafana dashboards
        dashboards_dir = os.path.join(output_dir, "dashboards")
        os.makedirs(dashboards_dir, exist_ok=True)
        
        for name, dashboard in self.grafana_dashboards.items():
            with open(os.path.join(dashboards_dir, f"{name}.json"), 'w') as f:
                json.dump(dashboard, f, indent=2)


class SecurityEventHandler:
    """Handler for security events and incident response"""
    
    def __init__(self, monitoring_config: MonitoringConfiguration):
        self.monitoring_config = monitoring_config
        self.incident_log = []
    
    def handle_critical_event(self, event_type: str, details: Dict[str, Any]):
        """Handle critical security events"""
        incident = {
            "id": f"INC-{len(self.incident_log) + 1:04d}",
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "status": "open",
            "actions_taken": []
        }
        
        # Determine response actions based on event type
        if event_type == "tampering_detected":
            incident["actions_taken"].extend([
                "Initiated audit log integrity verification",
                "Locked down affected keys",
                "Notified security team",
                "Created forensic snapshot"
            ])
        elif event_type == "brute_force_attempt":
            incident["actions_taken"].extend([
                "Blocked source IP",
                "Increased rate limiting",
                "Forced password reset for affected accounts",
                "Enhanced monitoring activated"
            ])
        
        self.incident_log.append(incident)
        return incident
    
    def generate_incident_report(self, incident_id: str) -> Dict[str, Any]:
        """Generate detailed incident report"""
        incident = next((i for i in self.incident_log if i["id"] == incident_id), None)
        
        if not incident:
            return {"error": "Incident not found"}
        
        return {
            "incident": incident,
            "impact_assessment": self._assess_impact(incident),
            "recommendations": self._generate_recommendations(incident),
            "timeline": self._generate_timeline(incident)
        }
    
    def _assess_impact(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the impact of a security incident"""
        return {
            "severity": "critical" if incident["event_type"] == "tampering_detected" else "high",
            "affected_systems": ["API Key Storage", "Audit Logs"],
            "data_exposure": "Unknown - investigation required",
            "business_impact": "Potential compromise of API credentials"
        }
    
    def _generate_recommendations(self, incident: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on incident"""
        recommendations = [
            "Review all recent API key accesses",
            "Rotate all potentially affected keys",
            "Enhance monitoring for suspicious patterns",
            "Review and update security policies"
        ]
        
        if incident["event_type"] == "tampering_detected":
            recommendations.extend([
                "Perform full security audit",
                "Review system access logs",
                "Consider implementing additional tamper-proofing measures"
            ])
        
        return recommendations
    
    def _generate_timeline(self, incident: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate incident timeline"""
        return [
            {
                "time": incident["timestamp"],
                "event": "Incident detected",
                "action": "Automated response initiated"
            },
            {
                "time": (datetime.fromisoformat(incident["timestamp"]) + 
                        timedelta(minutes=1)).isoformat(),
                "event": "Security team notified",
                "action": "Manual investigation started"
            },
            {
                "time": (datetime.fromisoformat(incident["timestamp"]) + 
                        timedelta(minutes=5)).isoformat(),
                "event": "Initial containment",
                "action": "Affected systems isolated"
            }
        ]


# Example usage
if __name__ == "__main__":
    from datetime import datetime
    
    # Create monitoring configuration
    config = MonitoringConfiguration()
    
    # Save configurations
    config.save_configurations("./monitoring")
    
    print("Monitoring configurations generated:")
    print(f"- Prometheus config: ./monitoring/prometheus.yml")
    print(f"- Alert rules: ./monitoring/alerts/security_alerts.yml")
    print(f"- Alertmanager config: ./monitoring/alertmanager.yml")
    print(f"- Grafana dashboards: ./monitoring/dashboards/")
    
    # Example incident handling
    handler = SecurityEventHandler(config)
    
    # Simulate a critical event
    incident = handler.handle_critical_event(
        "tampering_detected",
        {
            "affected_logs": 15,
            "detection_method": "signature_verification_failure",
            "suspected_tampering_time": datetime.now().isoformat()
        }
    )
    
    print(f"\nIncident created: {incident['id']}")
    
    # Generate incident report
    report = handler.generate_incident_report(incident['id'])
    print(f"\nIncident Report:")
    print(json.dumps(report, indent=2))