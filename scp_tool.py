"""
🔐 SCP Analysis Tool - Comprehensive Service Control Policy Analysis and Risk Assessment

📋 OVERVIEW:
This tool provides comprehensive analysis of AWS Service Control Policies (SCPs) to help
engineers understand policy impact, identify risks, and troubleshoot access issues.

🚀 KEY FEATURES:
1. 🔍 Policy Risk Analysis - Identifies high-risk policies that could break services
2. 🏢 Organizational Structure Analysis - Maps OUs, accounts, and policy inheritance
3. 🚫 Blocking Analysis - Shows what services/actions are being denied
4. 🎯 Specific Policy Deep-Dive - Analyze individual policies in detail
5. 🧪 Policy Testing - Test policy content before deployment
6. 📊 Compliance Reporting - Best practices and recommendations
7. 🔧 Interactive Troubleshooting - Real-time policy investigation
8. 📤 Export Capabilities - JSON and CSV export for further analysis

🔐 AUTHENTICATION OPTIONS:
- Cross-account role delegation (--role-arn)
- Named AWS profiles (--profile)
- Default credential chain

📖 CLOUDSHELL USAGE EXAMPLES:

# 🚀 QUICK START - First time analysis or quick overview
# Scenario: "What's currently being blocked in our organization?"
python3 scp_analysis.py --blocking-report-only

# 📊 EXPORT FOR ANALYSIS - Share results with team or import to Excel
# Scenario: "Need to present SCP findings to management or security team"
python3 scp_analysis.py --blocking-report-only --export-csv blocking.csv --export-json results.json

# 🔍 POLICY DRIFT DETECTION - Before/after change validation
# Scenario: Export current state BEFORE making changes, then compare AFTER
# Step 1: Export current state before changes
python3 scp_analysis.py --blocking-report-only --export-json before_changes.json
# Step 2: Make your SCP changes in AWS Console
# Step 3: Compare to detect what changed
python3 scp_analysis.py --detect-drift before_changes.json

# 🎯 RESOURCE IMPACT CHECK - Troubleshooting specific resource access
# Scenario: "Why can't I access this S3 bucket? Is it blocked by SCP?"
python3 scp_analysis.py --check-resource arn:aws:s3:::my-production-bucket

# 📈 SERVICE DEEP DIVE - Focus analysis on specific services
# Scenario: "Show me all SCP blocks affecting IAM, S3, and EC2 services"
python3 scp_analysis.py --service-analysis s3,iam,ec2,lambda

# 💡 OPTIMIZATION SUGGESTIONS (CloudShell)
python3 scp_analysis.py --suggest-least-privilege 123456789012

# 🔧 TROUBLESHOOTING COMBO (CloudShell)
python3 scp_analysis.py --blocking-report-only --service-analysis iam --export-csv iam_blocks.csv

# ⚡ PERFORMANCE OPTIMIZED (Large orgs)
python3 scp_analysis.py --blocking-report-only --export-json quick_$(date +%Y%m%d).json

# 🏢 CROSS-ACCOUNT (From Security Account)
python3 scp_analysis.py --role-arn arn:aws:iam::MGMT-ACCOUNT:role/SCPAnalysisRole --blocking-report-only

# 📋 COMPLIANCE CHECK (CloudShell)
python3 scp_analysis.py --service-analysis cloudtrail,config,guardduty --export-csv compliance.csv

# 🚨 EMERGENCY ANALYSIS - Quick check during incidents
# Scenario: "Incident response - can emergency role still access resources?"
python3 scp_analysis.py --check-resource arn:aws:iam::ACCOUNT:role/EmergencyRole --export-json emergency.json

# 🌍 REGION RESTRICTIONS - Analyze region-based blocks
# Scenario: "Which regions are blocked by our SCPs?"
python3 scp_analysis.py --region-analysis us-east-1,eu-west-1

# ⏰ TIME/IP CONDITIONS - Check conditional restrictions
# Scenario: "What time-based or IP restrictions do we have?"
python3 scp_analysis.py --condition-analysis

# 🔗 ACCOUNT INHERITANCE - Show policy inheritance chain
# Scenario: "What policies affect this account and where do they come from?"
python3 scp_analysis.py --inheritance-chain 123456789012

# 🛡️ SECURITY SERVICE PROTECTION - Check security coverage
# Scenario: "Are our security services protected from being disabled?"
python3 scp_analysis.py --security-coverage

# 🗑️ UNUSED POLICIES - Find ineffective policies
# Scenario: "Which policies can we clean up to reduce complexity?"
python3 scp_analysis.py --unused-policies --export-json unused.json

# 📏 POLICY COMPLEXITY - Check size and complexity
# Scenario: "Which policies are approaching AWS limits?"
python3 scp_analysis.py --policy-complexity --export-json size.json

🎯 USE CASES:
- 🔍 "What does this SCP policy actually do?"
- 🏢 "Which OUs and accounts are affected by this policy?"
- ⚠️ "What services will break if I apply this policy?"
- 🚫 "Why is this AWS action being denied?"
- 📊 "What's the overall risk posture of our SCPs?"
- 🧪 "Can I test this policy before deploying it?"
- 🔧 "Which policies are causing access issues?"

📊 REPORT TYPES:
1. Risk Analysis - High/Medium/Low risk policies
2. OU/Account Analysis - Organizational impact assessment
3. Blocking Analysis - What's being denied where
4. Detailed Policy Analysis - Statement-by-statement breakdown
5. Compliance Report - Best practices and recommendations

⚠️ PREREQUISITES:
- AWS CLI configured or appropriate IAM permissions
- Organizations read permissions
- SCP read permissions
- (Optional) Cross-account assume role permissions

🔧 REQUIRED PERMISSIONS:
- organizations:DescribeOrganization
- organizations:ListAccounts
- organizations:ListRoots
- organizations:ListPolicies
- organizations:DescribePolicy
- organizations:ListTargetsForPolicy
- organizations:ListOrganizationalUnitsForParent
- organizations:ListAccountsForParent
- organizations:ListPoliciesForTarget

📝 OUTPUT FORMATS:
- Console (colored, formatted output)
- JSON (structured data export)
- CSV (blocking analysis export)

"""

import boto3
import json
import argparse
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError
import re

class SCPAnalyzer:
    def __init__(self, session: boto3.Session):
        self.session = session
        self.org_client = session.client('organizations')
        self.iam_client = session.client('iam')
        self.sts_client = session.client('sts')
        
    def _safe_get_policy_content(self, content: Any) -> Dict[str, Any]:
        """Safely get policy content as dictionary"""
        if isinstance(content, str):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {}
        elif isinstance(content, dict):
            return content
        else:
            return {}
        
    def get_organization_info(self) -> Dict[str, Any]:
        """Get organization structure and basic info"""
        try:
            org = self.org_client.describe_organization()['Organization']
            accounts = self.org_client.list_accounts()['Accounts']
            roots = self.org_client.list_roots()['Roots']
            
            return {
                'organization': org,
                'accounts': accounts,
                'roots': roots,
                'total_accounts': len(accounts)
            }
        except ClientError as e:
            print(f"❌ Error getting organization info: {e}")
            return {}

    def get_all_policies(self) -> List[Dict[str, Any]]:
        try:
            policies = []
            paginator = self.org_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
                for policy in page['Policies']:
                    try:
                        policy_detail = self.org_client.describe_policy(PolicyId=policy['Id'])
                        policy_content = json.loads(policy_detail['Policy']['Content'])
                        
                        policies.append({
                            'id': policy['Id'],
                            'name': policy['Name'],
                            'description': policy.get('Description', ''),
                            'content': policy_content,
                            'aws_managed': policy['AwsManaged'],
                            'targets': self.get_policy_targets(policy['Id'])
                        })
                    except Exception as e:
                        print(f"⚠️ Warning: Skipping policy {policy.get('Name', 'Unknown')}: {e}")
                        continue
            
            return policies
        except ClientError as e:
            print(f"❌ Error getting policies: {e}")
            return []

    def get_policy_targets(self, policy_id: str) -> List[Dict[str, Any]]:
        try:
            targets = []
            paginator = self.org_client.get_paginator('list_targets_for_policy')
            
            for page in paginator.paginate(PolicyId=policy_id):
                targets.extend(page['Targets'])
            
            return targets
        except ClientError as e:
            return []

    def generate_simple_blocking_report(self) -> Dict[str, Any]:
        print("\n🚫 Analyzing SCP blocking patterns...")
        
        all_policies = self.get_all_policies()
        
        blocking_report = {
            'critical_blocks': [],
            'service_blocks': {},
            'account_impacts': {},
            'ou_impacts': {}
        }
        
        for policy in all_policies:
            try:
                # Check if policy is a dict
                if not isinstance(policy, dict):
                    continue
                
                # Check targets - skip policies without targets
                targets = policy.get('targets', [])
                if not targets:
                    continue
                    
                blocks = self._extract_blocking_actions(policy)
                
                # Add policy info to each block
                for block in blocks:
                    if isinstance(block, dict):
                        block['policy_name'] = policy.get('name', 'Unknown')
                        block['policy_id'] = policy.get('id', 'Unknown')
                
                for target in targets:
                    if not isinstance(target, dict):
                        continue
                    
                    target_type = target.get('Type', '')
                    target_id = target.get('TargetId', '')
                    
                    if target_type == 'ACCOUNT':
                        if target_id not in blocking_report['account_impacts']:
                            blocking_report['account_impacts'][target_id] = []
                        blocking_report['account_impacts'][target_id].extend(blocks)
                    
                    elif target_type == 'ORGANIZATIONAL_UNIT':
                        if target_id not in blocking_report['ou_impacts']:
                            blocking_report['ou_impacts'][target_id] = []
                        blocking_report['ou_impacts'][target_id].extend(blocks)
                    
                    for block in blocks:
                        if not isinstance(block, dict):
                            continue
                        
                        action = block.get('action', 'unknown')
                        service = action.split(':')[0] if ':' in action else 'unknown'
                        
                        if service not in blocking_report['service_blocks']:
                            blocking_report['service_blocks'][service] = 0
                        blocking_report['service_blocks'][service] += 1
                        
                        if block.get('severity') == 'CRITICAL':
                            blocking_report['critical_blocks'].append({
                                'policy_name': policy.get('name', 'Unknown'),
                                'policy_id': policy.get('id', 'Unknown'),
                                'target_type': target_type,
                                'target_id': target_id,
                                'action': action,
                                'impact': block.get('impact', 'Unknown impact')
                            })
                            
            except Exception as e:
                # Silently skip problematic policies
                continue
        
        return blocking_report

    def _extract_blocking_actions(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        blocks = []
        
        try:
            if not isinstance(policy, dict):
                return blocks
            
            content_raw = policy.get('content', {})
            content = self._safe_get_policy_content(content_raw)
            statements = content.get('Statement', [])
            
            for statement in statements:
                if not isinstance(statement, dict):
                    continue
                
                if statement.get('Effect') == 'Deny':
                    actions = statement.get('Action', [])
                    
                    if isinstance(actions, str):
                        actions = [actions]
                    elif not isinstance(actions, list):
                        continue
                    
                    for action in actions:
                        if not isinstance(action, str):
                            continue
                        
                        severity = 'LOW'
                        
                        if action == '*' or action.endswith(':*'):
                            severity = 'CRITICAL'
                        elif any(critical in action.lower() for critical in ['iam:', 'sts:', 'organizations:']):
                            severity = 'HIGH'
                        else:
                            severity = 'MEDIUM'
                        
                        blocks.append({
                            'action': action,
                            'impact': f"Blocks {action}",
                            'severity': severity,
                            'condition': statement.get('Condition', {})
                        })
                        
        except Exception:
            # Silently handle errors
            pass
        
        return blocks

    def analyze_region_restrictions(self, regions: List[str] = None) -> Dict[str, Any]:
        """Analyze region-based restrictions in SCPs"""
        try:
            all_policies = self.get_all_policies()
            region_report = {
                'blocked_regions': set(),
                'allowed_regions': set(),
                'region_policies': [],
                'unrestricted_policies': []
            }
            
            for policy in all_policies:
                has_region_condition = False
                for statement in policy['content'].get('Statement', []):
                    conditions = statement.get('Condition', {})
                    
                    # Check for region conditions
                    for condition_type, condition_values in conditions.items():
                        if 'aws:RequestedRegion' in str(condition_values):
                            has_region_condition = True
                            region_values = condition_values.get('aws:RequestedRegion', [])
                            if isinstance(region_values, str):
                                region_values = [region_values]
                            
                            if statement.get('Effect') == 'Deny':
                                region_report['blocked_regions'].update(region_values)
                            else:
                                region_report['allowed_regions'].update(region_values)
                            
                            region_report['region_policies'].append({
                                'policy_name': policy['name'],
                                'effect': statement.get('Effect'),
                                'regions': region_values
                            })
                
                if not has_region_condition:
                    region_report['unrestricted_policies'].append(policy['name'])
            
            region_report['blocked_regions'] = list(region_report['blocked_regions'])
            region_report['allowed_regions'] = list(region_report['allowed_regions'])
            
            return region_report
        except Exception as e:
            return {'error': f'Failed to analyze regions: {str(e)}'}
    
    def analyze_condition_restrictions(self) -> Dict[str, Any]:
        """Analyze time-based and IP-based restrictions"""
        try:
            all_policies = self.get_all_policies()
            condition_report = {
                'time_restrictions': [],
                'ip_restrictions': [],
                'mfa_requirements': [],
                'other_conditions': []
            }
            
            for policy in all_policies:
                for statement in policy['content'].get('Statement', []):
                    conditions = statement.get('Condition', {})
                    
                    for condition_type, condition_values in conditions.items():
                        if 'DateGreaterThan' in condition_type or 'DateLessThan' in condition_type:
                            condition_report['time_restrictions'].append({
                                'policy_name': policy['name'],
                                'condition_type': condition_type,
                                'values': condition_values
                            })
                        elif 'IpAddress' in condition_type or 'NotIpAddress' in condition_type:
                            condition_report['ip_restrictions'].append({
                                'policy_name': policy['name'],
                                'condition_type': condition_type,
                                'values': condition_values
                            })
                        elif 'aws:MultiFactorAuthPresent' in str(condition_values):
                            condition_report['mfa_requirements'].append({
                                'policy_name': policy['name'],
                                'condition_type': condition_type,
                                'values': condition_values
                            })
                        else:
                            condition_report['other_conditions'].append({
                                'policy_name': policy['name'],
                                'condition_type': condition_type,
                                'values': condition_values
                            })
            
            return condition_report
        except Exception as e:
            return {'error': f'Failed to analyze conditions: {str(e)}'}
    
    def analyze_inheritance_chain(self, account_id: str) -> Dict[str, Any]:
        """Show full SCP inheritance chain for an account"""
        try:
            org_info = self.get_organization_info()
            all_policies = self.get_all_policies()
            
            inheritance_chain = {
                'account_id': account_id,
                'inheritance_path': [],
                'effective_policies': [],
                'policy_sources': {}
            }
            
            # Find account's OU path
            account_ou_path = self._get_account_ou_path(account_id, org_info)
            inheritance_chain['inheritance_path'] = account_ou_path
            
            # Collect policies from each level
            for level in account_ou_path:
                level_policies = []
                for policy in all_policies:
                    for target in policy.get('targets', []):
                        if target.get('TargetId') == level['id']:
                            level_policies.append({
                                'policy_name': policy['name'],
                                'policy_id': policy['id'],
                                'source_level': level['name'],
                                'source_type': level['type']
                            })
                            inheritance_chain['effective_policies'].append(policy['name'])
                
                inheritance_chain['policy_sources'][level['name']] = level_policies
            
            return inheritance_chain
        except Exception as e:
            return {'error': f'Failed to analyze inheritance: {str(e)}'}
    
    def analyze_security_coverage(self) -> Dict[str, Any]:
        """Analyze if security services are properly protected"""
        try:
            all_policies = self.get_all_policies()
            security_services = [
                'cloudtrail', 'config', 'guardduty', 'securityhub', 'inspector',
                'macie', 'detective', 'accessanalyzer', 'sso', 'organizations'
            ]
            
            coverage_report = {
                'protected_services': {},
                'unprotected_services': [],
                'protection_gaps': [],
                'recommendations': []
            }
            
            for service in security_services:
                protecting_policies = set()  # Use set to avoid duplicates
                
                for policy in all_policies:
                    blocks = self._extract_blocking_actions(policy)
                    for block in blocks:
                        action = block.get('action', '')
                        # Check if action blocks this service (Disable, Delete, Stop, etc.)
                        if (action.startswith(f'{service}:') and 
                            any(dangerous_action in action for dangerous_action in 
                                ['Disable', 'Delete', 'Stop', 'Terminate', 'Remove', 'Detach'])):
                            protecting_policies.add(policy['name'])
                
                if protecting_policies:
                    coverage_report['protected_services'][service] = list(protecting_policies)
                else:
                    coverage_report['unprotected_services'].append(service)
                    coverage_report['protection_gaps'].append(f'{service} can be disabled/deleted')
            
            # Generate recommendations
            if coverage_report['unprotected_services']:
                coverage_report['recommendations'].append(
                    f"Consider protecting these services: {', '.join(coverage_report['unprotected_services'])}"
                )
            
            return coverage_report
        except Exception as e:
            return {'error': f'Failed to analyze security coverage: {str(e)}'}
    
    def detect_unused_policies(self) -> Dict[str, Any]:
        """Detect policies that are attached but have no blocking effect"""
        try:
            all_policies = self.get_all_policies()
            unused_report = {
                'unused_policies': [],
                'ineffective_policies': [],
                'optimization_opportunities': []
            }
            
            for policy in all_policies:
                # Skip AWS managed policies
                if policy.get('aws_managed', False):
                    continue
                
                # Check if policy has targets
                if not policy.get('targets', []):
                    unused_report['unused_policies'].append({
                        'policy_name': policy['name'],
                        'policy_id': policy['id'],
                        'reason': 'No targets attached'
                    })
                    continue
                
                # Check if policy has any deny statements
                blocks = self._extract_blocking_actions(policy)
                if not blocks:
                    unused_report['ineffective_policies'].append({
                        'policy_name': policy['name'],
                        'policy_id': policy['id'],
                        'reason': 'No blocking statements found'
                    })
            
            # Generate optimization opportunities
            if unused_report['unused_policies']:
                unused_report['optimization_opportunities'].append(
                    f"Remove {len(unused_report['unused_policies'])} unused policies"
                )
            
            if unused_report['ineffective_policies']:
                unused_report['optimization_opportunities'].append(
                    f"Review {len(unused_report['ineffective_policies'])} ineffective policies"
                )
            
            return unused_report
        except Exception as e:
            return {'error': f'Failed to detect unused policies: {str(e)}'}
    
    def analyze_policy_complexity(self) -> Dict[str, Any]:
        """Analyze policy size and complexity"""
        try:
            all_policies = self.get_all_policies()
            complexity_report = {
                'large_policies': [],
                'complex_policies': [],
                'size_warnings': [],
                'total_size': 0
            }
            
            for policy in all_policies:
                policy_json = json.dumps(policy['content'])
                policy_size = len(policy_json)
                statement_count = len(policy['content'].get('Statement', []))
                
                complexity_report['total_size'] += policy_size
                
                # Check size limits (AWS SCP limit is 5120 characters)
                if policy_size > 4000:
                    complexity_report['large_policies'].append({
                        'policy_name': policy['name'],
                        'size': policy_size,
                        'statements': statement_count
                    })
                
                # Check complexity
                if statement_count > 10:
                    complexity_report['complex_policies'].append({
                        'policy_name': policy['name'],
                        'statements': statement_count,
                        'size': policy_size
                    })
                
                # Size warnings
                if policy_size > 4500:
                    complexity_report['size_warnings'].append(
                        f"{policy['name']}: {policy_size} chars (approaching 5120 limit)"
                    )
            
            return complexity_report
        except Exception as e:
            return {'error': f'Failed to analyze complexity: {str(e)}'}
    
    def _get_account_ou_path(self, account_id: str, org_info: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get the OU path for an account"""
        try:
            # Simplified - would need full OU traversal in real implementation
            path = [
                {'id': 'r-root', 'name': 'Root', 'type': 'ROOT'},
                {'id': account_id, 'name': f'Account-{account_id}', 'type': 'ACCOUNT'}
            ]
            return path
        except:
            return []
            
    def analyze_policy_risk(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual policy for potential risks"""
        content = policy['content']
        risks = []
        severity = "LOW"
        
        # Check for overly restrictive policies
        if self._has_broad_deny(content):
            risks.append("Broad DENY statements that could break services")
            severity = "HIGH"
        
        # Check for specific high-risk patterns
        if self._blocks_critical_services(content):
            risks.append("Blocks access to critical AWS services")
            severity = "HIGH"
        
        # Check for IAM restrictions
        if self._restricts_iam_heavily(content):
            risks.append("Heavy IAM restrictions may prevent administration")
            severity = "MEDIUM"
        
        # Check for logging/monitoring blocks
        if self._blocks_logging_services(content):
            risks.append("Blocks logging/monitoring services")
            severity = "HIGH"
        
        # Check for emergency access issues
        if self._prevents_emergency_access(content):
            risks.append("May prevent emergency access scenarios")
            severity = "MEDIUM"
        
        return {
            'policy_name': policy['name'],
            'policy_id': policy['id'],
            'risks': risks,
            'severity': severity,
            'target_count': len(policy['targets']),
            'aws_managed': policy['aws_managed']
        }

    # 🆕 ENHANCED FEATURES - CRITICAL GAPS ADDRESSED
    
    def compare_policy_versions(self, old_policy_content: str, new_policy_content: str) -> Dict[str, Any]:
        """
        📊 Scenario 1: "Why did this work yesterday but not today?"
        Compare two policy versions to identify changes and their impact
        """
        try:
            old_policy = json.loads(old_policy_content) if isinstance(old_policy_content, str) else old_policy_content
            new_policy = json.loads(new_policy_content) if isinstance(new_policy_content, str) else new_policy_content
            
            changes = {
                'added_statements': [],
                'removed_statements': [],
                'modified_statements': [],
                'added_actions': [],
                'removed_actions': [],
                'impact_analysis': {
                    'risk_increase': False,
                    'new_blocks': [],
                    'removed_blocks': [],
                    'affected_services': set()
                }
            }
            
            # Extract actions from both policies
            old_actions = self._extract_all_actions(old_policy)
            new_actions = self._extract_all_actions(new_policy)
            
            # Find added/removed actions
            changes['added_actions'] = list(set(new_actions) - set(old_actions))
            changes['removed_actions'] = list(set(old_actions) - set(new_actions))
            
            # Analyze impact
            for action in changes['added_actions']:
                if self._is_critical_action(action):
                    changes['impact_analysis']['risk_increase'] = True
                    changes['impact_analysis']['new_blocks'].append(action)
                    if ':' in action:
                        changes['impact_analysis']['affected_services'].add(action.split(':')[0])
            
            changes['impact_analysis']['affected_services'] = list(changes['impact_analysis']['affected_services'])
            
            return changes
            
        except Exception as e:
            return {'error': f'Failed to compare policies: {str(e)}'}
    
    def detect_policy_conflicts(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        ⚔️ Scenario 2: Policy Conflict Detection
        Find conflicting policies that might cause unexpected behavior
        """
        conflicts = []
        
        # Group policies by target for conflict analysis
        target_policies = {}
        for policy in policies:
            for target in policy['targets']:
                target_id = target['TargetId']
                if target_id not in target_policies:
                    target_policies[target_id] = []
                target_policies[target_id].append(policy)
        
        # Check for conflicts within each target
        for target_id, target_policy_list in target_policies.items():
            if len(target_policy_list) > 1:
                target_conflicts = self._analyze_target_conflicts(target_id, target_policy_list)
                conflicts.extend(target_conflicts)
        
        return conflicts
    
    def trace_cross_account_access(self, source_account: str, target_account: str, action: str, role_arn: str = None) -> Dict[str, Any]:
        """
        🔗 Scenario 3: "Will this cross-account role assumption work?"
        Trace cross-account access permissions through SCP policies
        """
        try:
            trace_result = {
                'source_account': source_account,
                'target_account': target_account,
                'action': action,
                'role_arn': role_arn,
                'access_allowed': True,
                'blocking_policies': [],
                'trace_steps': []
            }
            
            # Get all policies affecting both accounts
            all_policies = self.get_all_policies()
            
            # Check source account restrictions
            source_blocks = self._check_account_restrictions(source_account, action, all_policies)
            if source_blocks:
                trace_result['access_allowed'] = False
                trace_result['blocking_policies'].extend(source_blocks)
                trace_result['trace_steps'].append(f"❌ Source account {source_account} blocked by SCP")
            else:
                trace_result['trace_steps'].append(f"✅ Source account {source_account} allows action")
            
            # Check target account restrictions
            target_blocks = self._check_account_restrictions(target_account, action, all_policies)
            if target_blocks:
                trace_result['access_allowed'] = False
                trace_result['blocking_policies'].extend(target_blocks)
                trace_result['trace_steps'].append(f"❌ Target account {target_account} blocked by SCP")
            else:
                trace_result['trace_steps'].append(f"✅ Target account {target_account} allows action")
            
            # Check sts:AssumeRole specifically for cross-account
            if role_arn:
                assume_role_blocks = self._check_account_restrictions(source_account, 'sts:AssumeRole', all_policies)
                if assume_role_blocks:
                    trace_result['access_allowed'] = False
                    trace_result['blocking_policies'].extend(assume_role_blocks)
                    trace_result['trace_steps'].append(f"❌ sts:AssumeRole blocked for {role_arn}")
                else:
                    trace_result['trace_steps'].append(f"✅ sts:AssumeRole allowed for {role_arn}")
            
            return trace_result
            
        except Exception as e:
            return {'error': f'Failed to trace cross-account access: {str(e)}'}
    
    def validate_break_glass_access(self, emergency_role_arn: str, critical_actions: List[str] = None) -> Dict[str, Any]:
        """
        🚨 Scenario 4: "Is our break-glass procedure actually working?"
        Validate emergency access roles can bypass SCP restrictions
        """
        if not critical_actions:
            critical_actions = [
                'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
                'ec2:StopInstances', 'ec2:TerminateInstances',
                'sts:AssumeRole', 'organizations:DetachPolicy'
            ]
        
        try:
            # Extract account ID from role ARN
            account_id = emergency_role_arn.split(':')[4]
            
            validation_result = {
                'emergency_role': emergency_role_arn,
                'account_id': account_id,
                'overall_status': 'FUNCTIONAL',
                'blocked_actions': [],
                'allowed_actions': [],
                'recommendations': []
            }
            
            all_policies = self.get_all_policies()
            
            # Test each critical action
            for action in critical_actions:
                blocks = self._check_account_restrictions(account_id, action, all_policies)
                if blocks:
                    validation_result['blocked_actions'].append({
                        'action': action,
                        'blocking_policies': [p['policy_name'] for p in blocks]
                    })
                    validation_result['overall_status'] = 'COMPROMISED'
                else:
                    validation_result['allowed_actions'].append(action)
            
            # Generate recommendations
            if validation_result['blocked_actions']:
                validation_result['recommendations'].append(
                    "Emergency access is compromised. Consider adding conditions to SCPs to allow break-glass roles."
                )
                validation_result['recommendations'].append(
                    "Review SCP conditions for emergency role exclusions using aws:PrincipalArn or aws:userid."
                )
            
            return validation_result
            
        except Exception as e:
            return {'error': f'Failed to validate break-glass access: {str(e)}'}
    
    def simulate_api_call(self, account_id: str, action: str, resource: str = '*', conditions: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        🧪 Scenario 5: Real-time API Call Simulation
        Simulate if an AWS API call would be allowed or denied by SCPs
        """
        try:
            simulation_result = {
                'account_id': account_id,
                'action': action,
                'resource': resource,
                'conditions': conditions or {},
                'result': 'ALLOWED',
                'blocking_policies': [],
                'evaluation_steps': []
            }
            
            all_policies = self.get_all_policies()
            
            # Check all policies affecting this account
            blocking_policies = self._check_account_restrictions(account_id, action, all_policies)
            
            if blocking_policies:
                simulation_result['result'] = 'DENIED'
                simulation_result['blocking_policies'] = blocking_policies
                simulation_result['evaluation_steps'].append(f"❌ Action {action} denied by SCP policies")
                
                for policy in blocking_policies:
                    simulation_result['evaluation_steps'].append(
                        f"   Policy: {policy['policy_name']} (ID: {policy['policy_id']})"
                    )
            else:
                simulation_result['evaluation_steps'].append(f"✅ Action {action} allowed by SCP policies")
            
            # Check resource-specific restrictions
            if resource != '*':
                resource_blocks = self._check_resource_restrictions(account_id, action, resource, all_policies)
                if resource_blocks:
                    simulation_result['result'] = 'DENIED'
                    simulation_result['blocking_policies'].extend(resource_blocks)
                    simulation_result['evaluation_steps'].append(f"❌ Resource {resource} specifically blocked")
            
            return simulation_result
            
        except Exception as e:
            return {'error': f'Failed to simulate API call: {str(e)}'}
    
    def map_to_compliance_frameworks(self, policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        📋 Scenario 6: Compliance Framework Mapping
        Map SCP policies to compliance requirements (SOC2, PCI-DSS, etc.)
        """
        compliance_mapping = {
            'SOC2': {
                'CC6.1': {'requirement': 'Logical access controls', 'mapped_policies': []},
                'CC6.2': {'requirement': 'Access credentials management', 'mapped_policies': []},
                'CC6.3': {'requirement': 'Network access controls', 'mapped_policies': []}
            },
            'PCI_DSS': {
                'Req_7': {'requirement': 'Restrict access by business need', 'mapped_policies': []},
                'Req_8': {'requirement': 'Identify users and authenticate access', 'mapped_policies': []}
            },
            'NIST': {
                'AC-2': {'requirement': 'Account Management', 'mapped_policies': []},
                'AC-3': {'requirement': 'Access Enforcement', 'mapped_policies': []}
            },
            'summary': {
                'total_mapped_policies': 0,
                'compliance_coverage': {},
                'gaps': []
            }
        }
        
        # Analyze each policy for compliance mapping
        for policy in policies:
            policy_actions = self._extract_all_actions(policy['content'])
            
            # Map to SOC2
            if any(action.startswith('iam:') for action in policy_actions):
                compliance_mapping['SOC2']['CC6.1']['mapped_policies'].append(policy['name'])
                compliance_mapping['SOC2']['CC6.2']['mapped_policies'].append(policy['name'])
            
            if any(action.startswith(('ec2:', 'vpc:')) for action in policy_actions):
                compliance_mapping['SOC2']['CC6.3']['mapped_policies'].append(policy['name'])
            
            # Map to PCI-DSS
            if any(action.startswith(('iam:', 's3:', 'kms:')) for action in policy_actions):
                compliance_mapping['PCI_DSS']['Req_7']['mapped_policies'].append(policy['name'])
                compliance_mapping['PCI_DSS']['Req_8']['mapped_policies'].append(policy['name'])
            
            # Map to NIST
            if any(action.startswith('iam:') for action in policy_actions):
                compliance_mapping['NIST']['AC-2']['mapped_policies'].append(policy['name'])
                compliance_mapping['NIST']['AC-3']['mapped_policies'].append(policy['name'])
        
        # Calculate summary
        total_mapped = set()
        for framework in ['SOC2', 'PCI_DSS', 'NIST']:
            for control in compliance_mapping[framework]:
                total_mapped.update(compliance_mapping[framework][control]['mapped_policies'])
        
        compliance_mapping['summary']['total_mapped_policies'] = len(total_mapped)
        
        # Calculate coverage percentages
        for framework in ['SOC2', 'PCI_DSS', 'NIST']:
            covered_controls = sum(1 for control in compliance_mapping[framework] 
                                 if compliance_mapping[framework][control]['mapped_policies'])
            total_controls = len(compliance_mapping[framework])
            compliance_mapping['summary']['compliance_coverage'][framework] = {
                'covered': covered_controls,
                'total': total_controls,
                'percentage': round((covered_controls / total_controls) * 100, 1)
            }
        
        return compliance_mapping
    
    # 🔧 HELPER METHODS FOR ENHANCED FEATURES
    
    def _extract_all_actions(self, policy_content: Dict[str, Any]) -> List[str]:
        """Extract all actions from a policy"""
        actions = []
        for statement in policy_content.get('Statement', []):
            stmt_actions = statement.get('Action', [])
            if isinstance(stmt_actions, str):
                actions.append(stmt_actions)
            elif isinstance(stmt_actions, list):
                actions.extend(stmt_actions)
        return actions
    
    def _is_critical_action(self, action: str) -> bool:
        """Check if an action is considered critical"""
        critical_prefixes = ['iam:', 'sts:', 'organizations:', 'cloudtrail:', 'config:']
        return any(action.startswith(prefix) for prefix in critical_prefixes) or action == '*'
    
    def _analyze_target_conflicts(self, target_id: str, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze conflicts between policies for a specific target"""
        conflicts = []
        
        # Check for overlapping deny statements
        deny_actions = {}
        for policy in policies:
            for statement in policy['content'].get('Statement', []):
                if statement.get('Effect') == 'Deny':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        if action not in deny_actions:
                            deny_actions[action] = []
                        deny_actions[action].append(policy['name'])
        
        # Find actions denied by multiple policies (potential redundancy)
        for action, policy_names in deny_actions.items():
            if len(policy_names) > 1:
                conflicts.append({
                    'type': 'redundant_deny',
                    'target_id': target_id,
                    'action': action,
                    'conflicting_policies': policy_names,
                    'severity': 'LOW',
                    'description': f"Action {action} is denied by multiple policies"
                })
        
        return conflicts
    
    def _check_account_restrictions(self, account_id: str, action: str, all_policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check if an account has restrictions for a specific action"""
        blocking_policies = []
        
        for policy in all_policies:
            # Check if policy applies to this account
            applies_to_account = False
            for target in policy['targets']:
                if target['TargetId'] == account_id or target['Type'] == 'ROOT':
                    applies_to_account = True
                    break
                elif target['Type'] == 'ORGANIZATIONAL_UNIT':
                    # Check if account is in this OU (simplified check)
                    applies_to_account = True  # Assume applies for now
            
            if applies_to_account and self._policy_denies_action(policy['content'], action):
                blocking_policies.append({
                    'policy_name': policy['name'],
                    'policy_id': policy['id']
                })
        
        return blocking_policies
    
    def _check_resource_restrictions(self, account_id: str, action: str, resource: str, all_policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check resource-specific restrictions"""
        # Simplified resource checking - can be enhanced based on specific needs
        return []  # Placeholder for resource-specific logic
    
    def _policy_denies_action(self, policy_content: Dict[str, Any], action: str) -> bool:
        """Check if a policy denies a specific action"""
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for policy_action in actions:
                    if self._action_matches(policy_action, action):
                        return True
        return False
    
    def _action_matches(self, policy_action: str, test_action: str) -> bool:
        """Check if a policy action matches a test action"""
        if policy_action == test_action:
            return True
        if policy_action == '*':
            return True
        if policy_action.endswith('*'):
            return test_action.startswith(policy_action[:-1])
        return False

    def _has_broad_deny(self, policy_content: Dict[str, Any]) -> bool:
        """Check for overly broad DENY statements"""
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for wildcards or broad service denials
                for action in actions:
                    if action == '*' or action.endswith(':*'):
                        return True
        return False

    def _blocks_critical_services(self, policy_content: Dict[str, Any]) -> bool:
        """Check if policy blocks critical AWS services"""
        # Ensure policy content is a dictionary
        if isinstance(policy_content, str):
            try:
                policy_content = json.loads(policy_content)
            except json.JSONDecodeError:
                return False
        
        critical_services = [
            'sts:', 'iam:', 'organizations:', 'cloudtrail:', 
            'config:', 'guardduty:', 'securityhub:'
        ]
        
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    for service in critical_services:
                        if action.startswith(service):
                            return True
        return False

    def _restricts_iam_heavily(self, policy_content: Dict[str, Any]) -> bool:
        """Check for heavy IAM restrictions"""
        iam_actions_count = 0
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if action.startswith('iam:'):
                        iam_actions_count += 1
        
        return iam_actions_count > 5

    def _blocks_logging_services(self, policy_content: Dict[str, Any]) -> bool:
        """Check if policy blocks logging/monitoring services"""
        logging_services = [
            'cloudtrail:', 'cloudwatch:', 'logs:', 'config:', 
            'xray:', 'inspector:', 'guardduty:'
        ]
        
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    for service in logging_services:
                        if action.startswith(service):
                            return True
        return False

    def _prevents_emergency_access(self, policy_content: Dict[str, Any]) -> bool:
        """Check if policy might prevent emergency access"""
        emergency_actions = [
            'sts:AssumeRole', 'iam:CreateRole', 'iam:AttachRolePolicy',
            'ec2:DescribeInstances', 'ec2:StopInstances'
        ]
        
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if action in emergency_actions:
                        return True
        return False

    def simulate_policy_impact(self, policy_content: Dict[str, Any], target_account: str) -> Dict[str, Any]:
        """Simulate what would break if this policy is applied"""
        potential_breaks = []
        
        # Analyze each statement
        for i, statement in enumerate(policy_content.get('Statement', [])):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    impact = self._analyze_action_impact(action)
                    if impact:
                        potential_breaks.append({
                            'statement_index': i,
                            'action': action,
                            'impact': impact,
                            'condition': statement.get('Condition', {})
                        })
        
        return {
            'target_account': target_account,
            'potential_breaks': potential_breaks,
            'total_restrictions': len(potential_breaks)
        }

    def _analyze_action_impact(self, action: str) -> Optional[str]:
        """Analyze the impact of denying a specific action"""
        impact_map = {
            'ec2:RunInstances': 'Cannot launch new EC2 instances',
            'ec2:TerminateInstances': 'Cannot terminate EC2 instances',
            's3:CreateBucket': 'Cannot create new S3 buckets',
            's3:DeleteBucket': 'Cannot delete S3 buckets',
            'iam:CreateUser': 'Cannot create new IAM users',
            'iam:DeleteUser': 'Cannot delete IAM users',
            'rds:CreateDBInstance': 'Cannot create RDS instances',
            'lambda:CreateFunction': 'Cannot create Lambda functions',
            'cloudformation:CreateStack': 'Cannot create CloudFormation stacks',
            'sts:AssumeRole': 'Cannot assume IAM roles (breaks cross-account access)',
            'organizations:*': 'Blocks all Organizations operations',
            'iam:*': 'Blocks all IAM operations (high risk)',
            'ec2:*': 'Blocks all EC2 operations',
            's3:*': 'Blocks all S3 operations'
        }
        
        # Direct match
        if action in impact_map:
            return impact_map[action]
        
        # Wildcard match
        for pattern, impact in impact_map.items():
            if pattern.endswith('*') and action.startswith(pattern[:-1]):
                return impact
        
        return None

    def generate_compliance_report(self, policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance and best practices report"""
        report = {
            'total_policies': len(policies),
            'aws_managed_count': sum(1 for p in policies if p['aws_managed']),
            'custom_policies_count': sum(1 for p in policies if not p['aws_managed']),
            'high_risk_policies': [],
            'recommendations': [],
            'compliance_issues': []
        }
        
        for policy in policies:
            risk_analysis = self.analyze_policy_risk(policy)
            if risk_analysis['severity'] == 'HIGH':
                report['high_risk_policies'].append(risk_analysis)
        
        # Generate recommendations
        if report['custom_policies_count'] > 10:
            report['recommendations'].append("Consider consolidating custom policies to reduce complexity")
        
        if len(report['high_risk_policies']) > 0:
            report['recommendations'].append("Review high-risk policies for potential service disruption")
        
        # Check for common compliance issues
        policy_names = [p['name'].lower() for p in policies]
        if not any('logging' in name or 'audit' in name for name in policy_names):
            report['compliance_issues'].append("No logging/audit focused policies found")
        
        return report

    def troubleshoot_access_issue(self, account_id: str, action: str) -> Dict[str, Any]:
        """Troubleshoot why a specific action might be denied"""
        try:
            # Get all policies affecting this account
            account_policies = []
            all_policies = self.get_all_policies()
            
            for policy in all_policies:
                for target in policy['targets']:
                    if target['TargetId'] == account_id or target['Type'] == 'ROOT':
                        account_policies.append(policy)
            
            # Check which policies might deny this action
            denying_policies = []
            for policy in account_policies:
                if self._policy_denies_action(policy['content'], action):
                    denying_policies.append({
                        'policy_name': policy['name'],
                        'policy_id': policy['id'],
                        'statement': self._get_denying_statement(policy['content'], action)
                    })
            
            return {
                'account_id': account_id,
                'action': action,
                'total_policies_checked': len(account_policies),
                'denying_policies': denying_policies,
                'is_likely_denied': len(denying_policies) > 0
            }
            
        except ClientError as e:
            return {'error': str(e)}

    def _policy_denies_action(self, policy_content: Dict[str, Any], action: str) -> bool:
        """Check if a policy denies a specific action"""
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for policy_action in actions:
                    if self._action_matches(policy_action, action):
                        return True
        return False

    def _get_denying_statement(self, policy_content: Dict[str, Any], action: str) -> Optional[Dict[str, Any]]:
        """Get the specific statement that denies an action"""
        for statement in policy_content.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for policy_action in actions:
                    if self._action_matches(policy_action, action):
                        return statement
        return None

    def _action_matches(self, policy_action: str, test_action: str) -> bool:
        """Check if a policy action matches a test action"""
        if policy_action == test_action:
            return True
        if policy_action == '*':
            return True
        if policy_action.endswith('*'):
            return test_action.startswith(policy_action[:-1])
        return False

    def get_organizational_units(self) -> List[Dict[str, Any]]:
        """Get all organizational units with hierarchy"""
        try:
            ous = []
            roots = self.org_client.list_roots()['Roots']
            
            for root in roots:
                # Get OUs under root
                root_ous = self._get_ous_recursive(root['Id'])
                ous.extend(root_ous)
            
            return ous
        except ClientError as e:
            print(f"❌ Error getting OUs: {e}")
            return []

    def _get_ous_recursive(self, parent_id: str, level: int = 0) -> List[Dict[str, Any]]:
        """Recursively get OUs and their children"""
        ous = []
        try:
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ou_info = {
                        'id': ou['Id'],
                        'name': ou['Name'],
                        'arn': ou['Arn'],
                        'level': level,
                        'parent_id': parent_id,
                        'accounts': self._get_accounts_in_ou(ou['Id']),
                        'policies': self._get_policies_for_target(ou['Id'])
                    }
                    ous.append(ou_info)
                    
                    # Get child OUs
                    child_ous = self._get_ous_recursive(ou['Id'], level + 1)
                    ous.extend(child_ous)
            
            return ous
        except ClientError as e:
            print(f"❌ Error getting child OUs for {parent_id}: {e}")
            return []

    def _get_accounts_in_ou(self, ou_id: str) -> List[Dict[str, Any]]:
        """Get accounts directly in an OU"""
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts_for_parent')
            
            for page in paginator.paginate(ParentId=ou_id):
                for account in page['Accounts']:
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account['Email'],
                        'status': account['Status']
                    })
            
            return accounts
        except ClientError as e:
            print(f"❌ Error getting accounts for OU {ou_id}: {e}")
            return []

    def _get_policies_for_target(self, target_id: str) -> List[Dict[str, Any]]:
        """Get policies attached to a specific target (OU or Account)"""
        try:
            policies = []
            paginator = self.org_client.get_paginator('list_policies_for_target')
            
            for page in paginator.paginate(TargetId=target_id, Filter='SERVICE_CONTROL_POLICY'):
                for policy in page['Policies']:
                    policies.append({
                        'id': policy['Id'],
                        'name': policy['Name'],
                        'type': policy['Type'],
                        'aws_managed': policy['AwsManaged']
                    })
            
            return policies
        except ClientError as e:
            print(f"❌ Error getting policies for target {target_id}: {e}")
            return []

    def generate_ou_account_report(self) -> Dict[str, Any]:
        """Generate comprehensive OU and Account analysis report"""
        print("\n🔍 Analyzing organizational structure...")
        
        # Get all OUs
        ous = self.get_organizational_units()
        
        # Get all accounts
        all_accounts = self.org_client.list_accounts()['Accounts']
        
        # Get all policies
        all_policies = self.get_all_policies()
        
        # Analyze each OU and Account
        ou_analysis = []
        account_analysis = []
        high_risk_targets = []
        
        # Analyze OUs
        for ou in ous:
            ou_risk = self._analyze_ou_risk(ou, all_policies)
            ou_analysis.append(ou_risk)
            
            if ou_risk['risk_level'] in ['HIGH', 'CRITICAL']:
                high_risk_targets.append({
                    'type': 'OU',
                    'id': ou['id'],
                    'name': ou['name'],
                    'risk_level': ou_risk['risk_level'],
                    'issues': ou_risk['issues'],
                    'affected_accounts': len(ou['accounts'])
                })
        
        # Analyze individual accounts
        for account in all_accounts:
            account_risk = self._analyze_account_risk(account, all_policies, ous)
            account_analysis.append(account_risk)
            
            if account_risk['risk_level'] in ['HIGH', 'CRITICAL']:
                high_risk_targets.append({
                    'type': 'Account',
                    'id': account['Id'],
                    'name': account['Name'],
                    'risk_level': account_risk['risk_level'],
                    'issues': account_risk['issues'],
                    'affected_accounts': 1
                })
        
        return {
            'ou_analysis': ou_analysis,
            'account_analysis': account_analysis,
            'high_risk_targets': high_risk_targets,
            'summary': {
                'total_ous': len(ous),
                'total_accounts': len(all_accounts),
                'high_risk_ous': len([ou for ou in ou_analysis if ou['risk_level'] in ['HIGH', 'CRITICAL']]),
                'high_risk_accounts': len([acc for acc in account_analysis if acc['risk_level'] in ['HIGH', 'CRITICAL']]),
                'total_policies': len(all_policies)
            }
        }

    def _analyze_ou_risk(self, ou: Dict[str, Any], all_policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze risk level for a specific OU"""
        issues = []
        risk_level = 'LOW'
        
        # Check policies attached to this OU
        ou_policies = ou['policies']
        
        # Analyze each policy for risk
        high_risk_policies = 0
        for policy_info in ou_policies:
            # Find full policy details
            full_policy = next((p for p in all_policies if p['id'] == policy_info['id']), None)
            if full_policy:
                policy_risk = self.analyze_policy_risk(full_policy)
                if policy_risk['severity'] == 'HIGH':
                    high_risk_policies += 1
                    issues.extend(policy_risk['risks'])
        
        # Determine risk level
        if high_risk_policies > 2:
            risk_level = 'CRITICAL'
        elif high_risk_policies > 0:
            risk_level = 'HIGH'
        elif len(ou_policies) > 5:
            risk_level = 'MEDIUM'
            issues.append(f"OU has {len(ou_policies)} policies attached - complexity risk")
        
        # Check for accounts without policies (inheritance only)
        accounts_without_direct_policies = 0
        for account in ou['accounts']:
            account_policies = self._get_policies_for_target(account['id'])
            if not account_policies:
                accounts_without_direct_policies += 1
        
        if accounts_without_direct_policies > 0:
            issues.append(f"{accounts_without_direct_policies} accounts rely solely on OU policy inheritance")
        
        return {
            'ou_id': ou['id'],
            'ou_name': ou['name'],
            'level': ou['level'],
            'risk_level': risk_level,
            'issues': issues,
            'policy_count': len(ou_policies),
            'account_count': len(ou['accounts']),
            'high_risk_policies': high_risk_policies
        }

    def _analyze_account_risk(self, account: Dict[str, Any], all_policies: List[Dict[str, Any]], ous: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze risk level for a specific account"""
        issues = []
        risk_level = 'LOW'
        
        # Get policies directly attached to account
        account_policies = self._get_policies_for_target(account['Id'])
        
        # Find which OU this account belongs to
        parent_ou = None
        for ou in ous:
            if any(acc['id'] == account['Id'] for acc in ou['accounts']):
                parent_ou = ou
                break
        
        # Analyze direct policies
        high_risk_policies = 0
        for policy_info in account_policies:
            full_policy = next((p for p in all_policies if p['id'] == policy_info['id']), None)
            if full_policy:
                policy_risk = self.analyze_policy_risk(full_policy)
                if policy_risk['severity'] == 'HIGH':
                    high_risk_policies += 1
                    issues.extend(policy_risk['risks'])
        
        # Check inherited policies from OU
        inherited_high_risk = 0
        if parent_ou:
            for policy_info in parent_ou['policies']:
                full_policy = next((p for p in all_policies if p['id'] == policy_info['id']), None)
                if full_policy:
                    policy_risk = self.analyze_policy_risk(full_policy)
                    if policy_risk['severity'] == 'HIGH':
                        inherited_high_risk += 1
        
        # Determine risk level
        total_high_risk = high_risk_policies + inherited_high_risk
        if total_high_risk > 3:
            risk_level = 'CRITICAL'
        elif total_high_risk > 1:
            risk_level = 'HIGH'
        elif total_high_risk > 0 or len(account_policies) > 3:
            risk_level = 'MEDIUM'
        
        # Special checks
        if account['Status'] != 'ACTIVE':
            issues.append(f"Account status is {account['Status']}")
            risk_level = 'HIGH'
        
        if not account_policies and not parent_ou:
            issues.append("Account has no direct policies and no OU inheritance")
            risk_level = 'MEDIUM'
        
        return {
            'account_id': account['Id'],
            'account_name': account['Name'],
            'account_email': account['Email'],
            'account_status': account['Status'],
            'risk_level': risk_level,
            'issues': issues,
            'direct_policy_count': len(account_policies),
            'inherited_policy_count': len(parent_ou['policies']) if parent_ou else 0,
            'parent_ou': parent_ou['name'] if parent_ou else 'ROOT',
            'high_risk_policies': high_risk_policies,
            'inherited_high_risk': inherited_high_risk
        }



    def analyze_specific_policy(self, policy_identifier: str) -> Dict[str, Any]:
        """Analyze a specific SCP policy by ID or name"""
        try:
            # Try to find policy by ID first, then by name
            policy = None
            all_policies = self.get_all_policies()
            
            for p in all_policies:
                if p['id'] == policy_identifier or p['name'] == policy_identifier:
                    policy = p
                    break
            
            if not policy:
                return {'error': f'Policy not found: {policy_identifier}'}
            
            return self._generate_detailed_policy_report(policy)
            
        except Exception as e:
            return {'error': str(e)}

    def analyze_policy_from_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze SCP policy from JSON file"""
        try:
            with open(file_path, 'r') as f:
                policy_content = json.load(f)
            
            # Create a mock policy object
            policy = {
                'id': 'FILE_POLICY',
                'name': f'Policy from {file_path}',
                'description': 'Policy loaded from file',
                'content': policy_content,
                'aws_managed': False,
                'targets': []  # No targets for file-based policy
            }
            
            return self._generate_detailed_policy_report(policy)
            
        except Exception as e:
            return {'error': f'Failed to load policy from file: {str(e)}'}

    def test_policy_content(self, policy_input: str) -> Dict[str, Any]:
        """Test SCP policy content (JSON string or file path)"""
        try:
            # Check if it's a file path
            if policy_input.endswith('.json') and os.path.exists(policy_input):
                return self.analyze_policy_from_file(policy_input)
            
            # Try to parse as JSON string
            try:
                policy_content = json.loads(policy_input)
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON format'}
            
            # Create a mock policy object
            policy = {
                'id': 'TEST_POLICY',
                'name': 'Test Policy',
                'description': 'Policy being tested',
                'content': policy_content,
                'aws_managed': False,
                'targets': []
            }
            
            return self._generate_detailed_policy_report(policy)
            
        except Exception as e:
            return {'error': str(e)}

    def _generate_detailed_policy_report(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive report for a specific policy"""
        report = {
            'policy_info': {
                'id': policy['id'],
                'name': policy['name'],
                'description': policy.get('description', ''),
                'aws_managed': policy['aws_managed']
            },
            'targets': [],
            'statements_analysis': [],
            'risk_assessment': {},
            'blocking_actions': [],
            'allowed_actions': [],
            'conditions_analysis': [],
            'impact_summary': {},
            'recommendations': []
        }
        
        # Analyze targets
        if policy['targets']:
            for target in policy['targets']:
                target_info = {
                    'type': target['Type'],
                    'id': target['TargetId'],
                    'name': self._get_target_name(target)
                }
                
                # Get affected accounts for this target
                if target['Type'] == 'ORGANIZATIONAL_UNIT':
                    target_info['affected_accounts'] = self._get_accounts_in_ou(target['TargetId'])
                elif target['Type'] == 'ACCOUNT':
                    target_info['affected_accounts'] = [{'id': target['TargetId']}]
                elif target['Type'] == 'ROOT':
                    all_accounts = self.org_client.list_accounts()['Accounts']
                    target_info['affected_accounts'] = [{'id': acc['Id'], 'name': acc['Name']} for acc in all_accounts]
                
                report['targets'].append(target_info)
        
        # Analyze each statement
        for i, statement in enumerate(policy['content'].get('Statement', [])):
            stmt_analysis = {
                'statement_index': i,
                'effect': statement.get('Effect'),
                'actions': statement.get('Action', []),
                'resources': statement.get('Resource', []),
                'conditions': statement.get('Condition', {}),
                'principals': statement.get('Principal', {}),
                'analysis': self._analyze_statement(statement)
            }
            report['statements_analysis'].append(stmt_analysis)
        
        # Risk assessment
        report['risk_assessment'] = self.analyze_policy_risk(policy)
        
        # Extract blocking and allowing actions
        report['blocking_actions'] = self._extract_blocking_actions(policy)
        report['allowed_actions'] = self._extract_allowing_actions(policy)
        
        # Analyze conditions
        report['conditions_analysis'] = self._analyze_policy_conditions(policy)
        
        # Generate impact summary
        report['impact_summary'] = self._generate_impact_summary(policy, report)
        
        # Generate recommendations
        report['recommendations'] = self._generate_policy_recommendations(policy, report)
        
        return report

    def _get_target_name(self, target: Dict[str, Any]) -> str:
        """Get human-readable name for a target"""
        try:
            if target['Type'] == 'ACCOUNT':
                account = self.org_client.describe_account(AccountId=target['TargetId'])
                return account['Account']['Name']
            elif target['Type'] == 'ORGANIZATIONAL_UNIT':
                ou = self.org_client.describe_organizational_unit(OrganizationalUnitId=target['TargetId'])
                return ou['OrganizationalUnit']['Name']
            elif target['Type'] == 'ROOT':
                return 'Organization Root'
            else:
                return target['TargetId']
        except:
            return target['TargetId']

    def _analyze_statement(self, statement: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual policy statement"""
        analysis = {
            'statement_type': 'Unknown',
            'scope': 'Unknown',
            'risk_level': 'LOW',
            'issues': [],
            'services_affected': []
        }
        
        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Determine statement type
        if effect == 'Deny':
            analysis['statement_type'] = 'Restrictive (Deny)'
        elif effect == 'Allow':
            analysis['statement_type'] = 'Permissive (Allow)'
        
        # Analyze scope
        if '*' in actions:
            analysis['scope'] = 'All Actions'
            analysis['risk_level'] = 'CRITICAL'
            analysis['issues'].append('Affects all AWS actions')
        elif any(action.endswith(':*') for action in actions):
            analysis['scope'] = 'Service-wide'
            analysis['risk_level'] = 'HIGH'
        else:
            analysis['scope'] = 'Specific Actions'
        
        # Extract affected services
        services = set()
        for action in actions:
            if ':' in action:
                service = action.split(':')[0]
                services.add(service)
        analysis['services_affected'] = list(services)
        
        # Check for critical services
        critical_services = ['iam', 'sts', 'organizations', 'cloudtrail']
        if any(service in critical_services for service in services):
            analysis['risk_level'] = 'HIGH'
            analysis['issues'].append('Affects critical AWS services')
        
        return analysis

    def _extract_allowing_actions(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all allowing actions from a policy"""
        allows = []
        
        for statement in policy['content'].get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    allows.append({
                        'action': action,
                        'condition': statement.get('Condition', {}),
                        'resource': statement.get('Resource', '*')
                    })
        
        return allows

    def _analyze_policy_conditions(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze conditions in policy statements"""
        conditions_analysis = []
        
        for i, statement in enumerate(policy['content'].get('Statement', [])):
            conditions = statement.get('Condition', {})
            if conditions:
                for condition_type, condition_values in conditions.items():
                    analysis = {
                        'statement_index': i,
                        'condition_type': condition_type,
                        'condition_values': condition_values,
                        'analysis': self._interpret_condition(condition_type, condition_values)
                    }
                    conditions_analysis.append(analysis)
        
        return conditions_analysis

    def _interpret_condition(self, condition_type: str, condition_values: Dict[str, Any]) -> str:
        """Interpret what a condition does in plain English"""
        interpretations = {
            'StringEquals': 'Requires exact string match',
            'StringLike': 'Allows wildcard string matching',
            'IpAddress': 'Restricts by IP address',
            'DateGreaterThan': 'Applies after specific date',
            'DateLessThan': 'Applies before specific date',
            'Bool': 'Requires boolean condition',
            'NumericLessThan': 'Requires numeric value less than',
            'NumericGreaterThan': 'Requires numeric value greater than'
        }
        
        base_interpretation = interpretations.get(condition_type, f'Applies {condition_type} condition')
        
        # Add specific details based on common condition keys
        if 'aws:RequestedRegion' in condition_values:
            return f"{base_interpretation} for specific AWS regions: {condition_values['aws:RequestedRegion']}"
        elif 'aws:userid' in condition_values:
            return f"{base_interpretation} for specific user IDs"
        elif 'aws:PrincipalTag' in condition_values:
            return f"{base_interpretation} based on principal tags"
        
        return base_interpretation

    def _generate_impact_summary(self, policy: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate high-level impact summary"""
        summary = {
            'total_targets': len(report['targets']),
            'total_affected_accounts': 0,
            'services_blocked': set(),
            'services_allowed': set(),
            'critical_blocks': 0,
            'high_risk_statements': 0
        }
        
        # Count affected accounts
        for target in report['targets']:
            summary['total_affected_accounts'] += len(target.get('affected_accounts', []))
        
        # Analyze blocking actions
        for block in report['blocking_actions']:
            if ':' in block['action']:
                service = block['action'].split(':')[0]
                summary['services_blocked'].add(service)
            if block['severity'] == 'CRITICAL':
                summary['critical_blocks'] += 1
        
        # Analyze allowing actions
        for allow in report['allowed_actions']:
            if ':' in allow['action']:
                service = allow['action'].split(':')[0]
                summary['services_allowed'].add(service)
        
        # Count high-risk statements
        for stmt in report['statements_analysis']:
            if stmt['analysis']['risk_level'] in ['HIGH', 'CRITICAL']:
                summary['high_risk_statements'] += 1
        
        # Convert sets to lists for JSON serialization
        summary['services_blocked'] = list(summary['services_blocked'])
        summary['services_allowed'] = list(summary['services_allowed'])
        
        return summary

    def _generate_policy_recommendations(self, policy: Dict[str, Any], report: Dict[str, Any]) -> List[str]:
        """Generate recommendations for policy improvement"""
        recommendations = []
        
        # Check for overly broad permissions
        if report['impact_summary']['critical_blocks'] > 0:
            recommendations.append("Consider narrowing overly broad DENY statements that use wildcards")
        
        # Check for missing conditions
        statements_without_conditions = sum(1 for stmt in report['statements_analysis'] 
                                          if not stmt['conditions'])
        if statements_without_conditions > 0:
            recommendations.append("Consider adding conditions to statements for more granular control")
        
        # Check for high-risk services
        critical_services = ['iam', 'sts', 'organizations']
        blocked_critical = [s for s in report['impact_summary']['services_blocked'] 
                           if s in critical_services]
        if blocked_critical:
            recommendations.append(f"Review restrictions on critical services: {', '.join(blocked_critical)}")
        
        # Check for complexity
        if len(report['statements_analysis']) > 10:
            recommendations.append("Policy is complex with many statements - consider splitting into multiple policies")
        
        # Check for unused Allow statements in SCP
        if report['allowed_actions']:
            recommendations.append("SCPs typically use DENY - review if ALLOW statements are necessary")
        
        return recommendations

def setup_session(args) -> boto3.Session:
    """Setup boto3 session with delegation support"""
    if args.role_arn:
        # Assume role for cross-account access
        sts = boto3.client('sts')
        try:
            response = sts.assume_role(
                RoleArn=args.role_arn,
                RoleSessionName='SCPAnalysisSession'
            )
            credentials = response['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except ClientError as e:
            print(f"❌ Failed to assume role {args.role_arn}: {e}")
            sys.exit(1)
    
    elif args.profile:
        # Use named profile
        try:
            return boto3.Session(profile_name=args.profile)
        except Exception as e:
            print(f"❌ Failed to use profile {args.profile}: {e}")
            sys.exit(1)
    
    else:
        # Use default credentials
        return boto3.Session()

def print_ou_account_report(analyzer: SCPAnalyzer):
    """Print comprehensive OU and Account analysis report"""
    report = analyzer.generate_ou_account_report()
    
    print("\n" + "="*80)
    print("🏢 ORGANIZATIONAL UNIT & ACCOUNT ANALYSIS")
    print("="*80)
    
    # Summary
    summary = report['summary']
    print(f"\n📊 SUMMARY:")
    print(f"   Total OUs: {summary['total_ous']}")
    print(f"   Total Accounts: {summary['total_accounts']}")
    print(f"   High Risk OUs: {summary['high_risk_ous']}")
    print(f"   High Risk Accounts: {summary['high_risk_accounts']}")
    print(f"   Total Policies: {summary['total_policies']}")
    
    # High Risk Targets
    if report['high_risk_targets']:
        print(f"\n🚨 HIGH RISK TARGETS ({len(report['high_risk_targets'])}):")        
        for target in sorted(report['high_risk_targets'], key=lambda x: x['risk_level'], reverse=True):
            risk_icon = "🔴" if target['risk_level'] == 'CRITICAL' else "🟡"
            print(f"  {risk_icon} {target['type']}: {target['name']} (ID: {target['id']})")
            print(f"     Risk Level: {target['risk_level']}")
            print(f"     Affected Accounts: {target['affected_accounts']}")
            if target['issues']:
                print(f"     Issues:")
                for issue in target['issues'][:]:
                    print(f"       • {issue}")
            print()
    
    # OU Analysis Details
    high_risk_ous = [ou for ou in report['ou_analysis'] if ou['risk_level'] in ['HIGH', 'CRITICAL']]
    if high_risk_ous:
        print(f"\n🏢 HIGH RISK ORGANIZATIONAL UNITS:")
        for ou in high_risk_ous:
            print(f"  📁 {ou['ou_name']} (Level {ou['level']})")
            print(f"     Policies: {ou['policy_count']} | Accounts: {ou['account_count']}")
            print(f"     High Risk Policies: {ou['high_risk_policies']}")
            if ou['issues']:
                for issue in ou['issues'][:2]:
                    print(f"     • {issue}")
            print()
    
    # Account Analysis Details
    high_risk_accounts = [acc for acc in report['account_analysis'] if acc['risk_level'] in ['HIGH', 'CRITICAL']]
    if high_risk_accounts:
        print(f"\n👤 HIGH RISK ACCOUNTS:")
        for acc in high_risk_accounts[:]:
            print(f"  🔐 {acc['account_name']} ({acc['account_id']})")
            print(f"     Parent OU: {acc['parent_ou']} | Status: {acc['account_status']}")
            print(f"     Direct Policies: {acc['direct_policy_count']} | Inherited: {acc['inherited_policy_count']}")
            if acc['issues']:
                for issue in acc['issues'][:2]:
                    print(f"     • {issue}")
            print()

def print_blocking_report(analyzer: SCPAnalyzer):
    """Print comprehensive blocking report with policy details"""
    report = analyzer.generate_simple_blocking_report()
    
    print("\n" + "="*80)
    print("🚫 SCP BLOCKING ANALYSIS REPORT")
    print("="*80)
    
    # Critical Blocks with Policy Details
    if report['critical_blocks']:
        print(f"\n🔴 CRITICAL BLOCKS ({len(report['critical_blocks'])}):")        
        for block in report['critical_blocks'][:]:
            print(f"  ❌ Policy: {block['policy_name']} (ID: {block.get('policy_id', 'Unknown')})")
            print(f"     Target: {block['target_type']} ({block['target_id']})")
            print(f"     Action: {block['action']}")
            print(f"     Impact: {block['impact']}")
            print()
    
    # Service Blocks Summary with Policy Breakdown
    if report['service_blocks']:
        print(f"\n📊 SERVICES BEING BLOCKED:")
        sorted_services = sorted(report['service_blocks'].items(), key=lambda x: x[1], reverse=True)
        for service, count in sorted_services:  # Show ALL services
            print(f"  🔒 {service}: {count} blocking rules (individual deny statements)")
            
            # Show detailed policy and rule breakdown
            all_policies = analyzer.get_all_policies()
            service_details = {}
            
            for policy in all_policies:
                blocks = analyzer._extract_blocking_actions(policy)
                policy_blocks = []
                for block in blocks:
                    action = block.get('action', '')
                    if action.startswith(f'{service}:'):
                        policy_blocks.append(action)
                
                if policy_blocks:
                    service_details[policy['name']] = {
                        'policy_id': policy['id'],
                        'actions': policy_blocks
                    }
            
            if service_details:
                print(f"     Blocked by:")
                for policy_name, details in service_details.items():
                    policy_id_short = details['policy_id'][:8] + "..."
                    print(f"       • {policy_name} ({policy_id_short})")
                    for action in details['actions']:
                        print(f"         - {action}")
                print()
                
    
    # Account Impacts with Policy Details - ENHANCED
    if report['account_impacts']:
        # Filter out accounts with 0 blocks
        accounts_with_blocks = {k: v for k, v in report['account_impacts'].items() if len(v) > 0}
        
        if accounts_with_blocks:
            print(f"\n👤 ACCOUNTS WITH BLOCKS ({len(accounts_with_blocks)}):")        
            for account_id, blocks in accounts_with_blocks.items():  # Show ALL accounts with blocks
                critical_blocks = len([b for b in blocks if b.get('severity') == 'CRITICAL'])
                high_blocks = len([b for b in blocks if b.get('severity') == 'HIGH'])
                medium_blocks = len([b for b in blocks if b.get('severity') == 'MEDIUM'])
                
                print(f"  🔐 Account {account_id}: {len(blocks)} total blocks")
                if critical_blocks > 0:
                    print(f"     🔴 Critical: {critical_blocks}")
                if high_blocks > 0:
                    print(f"     🟡 High: {high_blocks}")
                if medium_blocks > 0:
                    print(f"     🟠 Medium: {medium_blocks}")
                
                # Show detailed blocking policies and their specific actions
                policy_details = {}
                for block in blocks:
                    policy_name = block.get('policy_name', 'Unknown')
                    policy_id = block.get('policy_id', 'Unknown')
                    action = block.get('action', 'Unknown')
                    
                    if policy_name not in policy_details:
                        policy_details[policy_name] = {
                            'policy_id': policy_id,
                            'actions': [],
                            'count': 0
                        }
                    policy_details[policy_name]['actions'].append(action)
                    policy_details[policy_name]['count'] += 1
                
                if policy_details:
                    print(f"     Blocking Policies:")
                    for policy_name, details in policy_details.items():
                        policy_id_short = details['policy_id'][:8] + "..." if len(details['policy_id']) > 8 else details['policy_id']
                        print(f"       • {policy_name} ({policy_id_short}) - {details['count']} blocks")
                        # Show ALL actions - no truncation
                        for action in details['actions']:
                            print(f"         - {action}")
                print()
        else:
            print(f"\n👤 No accounts have blocking policies applied directly")
    
    # OU Impacts with Policy Details
    if report['ou_impacts']:
        print(f"\n🏢 OUs WITH BLOCKS ({len(report['ou_impacts'])}):")        
        for ou_id, blocks in list(report['ou_impacts'].items())[:]:
            critical_blocks = len([b for b in blocks if b.get('severity') == 'CRITICAL'])
            high_blocks = len([b for b in blocks if b.get('severity') == 'HIGH'])
            
            print(f"  📁 OU {ou_id}: {len(blocks)} total blocks")
            if critical_blocks > 0:
                print(f"     🔴 Critical blocks: {critical_blocks}")
            if high_blocks > 0:
                print(f"     🟡 High blocks: {high_blocks}")
            
            # Show unique policies affecting this OU
            unique_policies = set()
            for block in blocks:
                policy_name = block.get('policy_name', 'Unknown')
                unique_policies.add(policy_name)
            
            if unique_policies:
                print(f"     Policies: {', '.join(list(unique_policies)[:])}")
                if len(unique_policies) > 3:
                    pass
                    
            print()
    
    # Summary Statistics
    print(f"\n📈 SUMMARY STATISTICS:")
    total_policies_with_blocks = len(set(block.get('policy_name', '') for blocks in report['account_impacts'].values() for block in blocks))
    total_unique_actions = len(set(block.get('action', '') for blocks in report['account_impacts'].values() for block in blocks))
    
    print(f"  📋 Total Policies with Blocks: {total_policies_with_blocks}")
    print(f"  🎯 Unique Actions Blocked: {total_unique_actions}")
    print(f"  🏢 OUs Affected: {len(report['ou_impacts'])}")
    print(f"  👤 Accounts Analyzed: {len(report['account_impacts'])}")

def print_risk_analysis(policies: List[Dict[str, Any]], analyzer: SCPAnalyzer):
    """Print comprehensive risk analysis"""
    print("\n" + "="*80)
    print("🔍 SCP RISK ANALYSIS REPORT")
    print("="*80)
    
    high_risk = []
    medium_risk = []
    low_risk = []
    
    for policy in policies:
        risk = analyzer.analyze_policy_risk(policy)
        if risk['severity'] == 'HIGH':
            high_risk.append(risk)
        elif risk['severity'] == 'MEDIUM':
            medium_risk.append(risk)
        else:
            low_risk.append(risk)
    
    # High Risk Policies
    if high_risk:
        print(f"\n🚨 HIGH RISK POLICIES ({len(high_risk)}):")
        for risk in high_risk:
            print(f"  ❌ {risk['policy_name']} (ID: {risk['policy_id']})")
            print(f"     Targets: {risk['target_count']} | AWS Managed: {risk['aws_managed']}")
            for r in risk['risks']:
                print(f"     • {r}")
            print()
    
    # Medium Risk Policies
    if medium_risk:
        print(f"\n⚠️  MEDIUM RISK POLICIES ({len(medium_risk)}):")
        for risk in medium_risk:
            print(f"  🟡 {risk['policy_name']} (ID: {risk['policy_id']})")
            for r in risk['risks']:
                print(f"     • {r}")
            print()
    
    print(f"\n📊 SUMMARY:")
    print(f"   Total Policies: {len(policies)}")
    print(f"   High Risk: {len(high_risk)}")
    print(f"   Medium Risk: {len(medium_risk)}")
    print(f"   Low Risk: {len(low_risk)}")

def print_what_if_analysis(policies: List[Dict[str, Any]], analyzer: SCPAnalyzer, target_account: str):
    """Print what-if scenario analysis"""
    print("\n" + "="*80)
    print(f"🎯 WHAT-IF ANALYSIS FOR ACCOUNT: {target_account}")
    print("="*80)
    
    for policy in policies[:]:
        print(f"\n📋 Policy: {policy['name']}")
        simulation = analyzer.simulate_policy_impact(policy['content'], target_account)
        
        if simulation['potential_breaks']:
            print(f"   ⚠️  Potential Issues ({len(simulation['potential_breaks'])}):")
            for break_item in simulation['potential_breaks'][:]:
                print(f"     • {break_item['action']}: {break_item['impact']}")
        else:
            print("   ✅ No obvious breaking changes detected")

def interactive_troubleshoot(analyzer: SCPAnalyzer):
    """Interactive troubleshooting mode"""
    print("\n" + "="*80)
    print("🔧 INTERACTIVE SCP TROUBLESHOOTING")
    print("="*80)
    print("Enter 'quit' to exit")
    
    while True:
        print("\nTroubleshooting Options:")
        print("1. Check why an action is denied")
        print("2. Analyze policy impact")
        print("3. List policies for account")
        
        choice = input("\nSelect option (1-3) or 'quit': ").strip()
        
        if choice.lower() == 'quit':
            break
        elif choice == '1':
            account_id = input("Enter Account ID: ").strip()
            action = input("Enter Action (e.g., s3:CreateBucket): ").strip()
            
            result = analyzer.troubleshoot_access_issue(account_id, action)
            if 'error' in result:
                print(f"❌ Error: {result['error']}")
            else:
                print(f"\n🔍 Analysis for {action} in account {account_id}:")
                print(f"   Policies checked: {result['total_policies_checked']}")
                print(f"   Likely denied: {'YES' if result['is_likely_denied'] else 'NO'}")
                
                if result['denying_policies']:
                    print("   Denying policies:")
                    for policy in result['denying_policies']:
                        print(f"     • {policy['policy_name']} (ID: {policy['policy_id']})")
        
        elif choice == '2':
            print("Policy impact analysis - Feature coming soon!")
        elif choice == '3':
            print("Account policy listing - Feature coming soon!")
        else:
            print("Invalid option. Please try again.")

def print_detailed_policy_report(report: Dict[str, Any]):
    """Print detailed analysis report for a specific policy"""
    print("\n" + "="*80)
    print("📋 DETAILED SCP POLICY ANALYSIS")
    print("="*80)
    
    # Policy Information
    policy_info = report['policy_info']
    print(f"\n📄 POLICY INFORMATION:")
    print(f"   Name: {policy_info['name']}")
    print(f"   ID: {policy_info['id']}")
    print(f"   AWS Managed: {policy_info['aws_managed']}")
    if policy_info['description']:
        print(f"   Description: {policy_info['description']}")
    
    # Targets and Impact
    if report['targets']:
        print(f"\n🎯 TARGETS & IMPACT:")
        total_accounts = 0
        for target in report['targets']:
            print(f"   {target['type']}: {target.get('name', target['id'])}")
            affected_accounts = len(target.get('affected_accounts', []))
            total_accounts += affected_accounts
            print(f"     Affected Accounts: {affected_accounts}")
            
            # Show some account details
            if target.get('affected_accounts') and len(target['affected_accounts']) <= 5:
                for acc in target['affected_accounts']:
                    print(f"       • {acc.get('name', acc['id'])} ({acc['id']})")
            elif len(target.get('affected_accounts', [])) > 5:
                print(f"       • {target['affected_accounts'][0].get('name', target['affected_accounts'][0]['id'])} and {len(target['affected_accounts'])-1} others...")
        
        print(f"\n   📊 Total Affected Accounts: {total_accounts}")
    else:
        print(f"\n🎯 TARGETS: No targets (policy from file/test)")
    
    # Impact Summary
    impact = report['impact_summary']
    print(f"\n📊 IMPACT SUMMARY:")
    print(f"   Services Blocked: {len(impact['services_blocked'])} ({', '.join(impact['services_blocked'][:])})")
    if len(impact['services_blocked']) > 10:
        pass
        
    
    if impact['services_allowed']:
        print(f"   Services Allowed: {len(impact['services_allowed'])} ({', '.join(impact['services_allowed'])})")
    
    print(f"   Critical Blocks: {impact['critical_blocks']}")
    print(f"   High Risk Statements: {impact['high_risk_statements']}")
    
    # Risk Assessment
    risk = report['risk_assessment']
    print(f"\n⚠️  RISK ASSESSMENT:")
    print(f"   Overall Risk Level: {risk['severity']}")
    if risk['risks']:
        print(f"   Identified Risks:")
        for r in risk['risks']:
            print(f"     • {r}")
    
    # Statement Analysis
    print(f"\n📝 STATEMENT ANALYSIS ({len(report['statements_analysis'])} statements):")
    for stmt in report['statements_analysis']:
        analysis = stmt['analysis']
        print(f"   Statement {stmt['statement_index'] + 1}: {analysis['statement_type']}")
        print(f"     Effect: {stmt['effect']} | Scope: {analysis['scope']} | Risk: {analysis['risk_level']}")
        
        if analysis['services_affected']:
            print(f"     Services: {', '.join(analysis['services_affected'])}")
        
        if analysis['issues']:
            for issue in analysis['issues']:
                print(f"     ⚠️  {issue}")
        
        # Show some actions
        actions = stmt['actions']
        if isinstance(actions, list) and len(actions) <= 3:
            print(f"     Actions: {', '.join(actions)}")
        elif isinstance(actions, list) and len(actions) > 3:
            print(f"     Actions: {', '.join(actions[:])} ... (+{len(actions)-3} more)")
        elif isinstance(actions, str):
            print(f"     Actions: {actions}")
        
        print()
    
    # Blocking Actions
    if report['blocking_actions']:
        print(f"\n🚫 BLOCKING ACTIONS ({len(report['blocking_actions'])}):")        
        critical_blocks = [b for b in report['blocking_actions'] if b['severity'] == 'CRITICAL']
        high_blocks = [b for b in report['blocking_actions'] if b['severity'] == 'HIGH']
        
        if critical_blocks:
            print(f"   🔴 Critical Blocks ({len(critical_blocks)}):")
            for block in critical_blocks[:]:
                print(f"     • {block['action']}: {block['impact']}")
        
        if high_blocks:
            print(f"   🟡 High Risk Blocks ({len(high_blocks)}):")
            for block in high_blocks[:]:
                print(f"     • {block['action']}: {block['impact']}")
    
    # Conditions Analysis
    if report['conditions_analysis']:
        print(f"\n🔧 CONDITIONS ANALYSIS:")
        for condition in report['conditions_analysis']:
            print(f"   Statement {condition['statement_index'] + 1}: {condition['condition_type']}")
            print(f"     {condition['analysis']}")
    
    # Recommendations
    if report['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"   • {rec}")
    
    print(f"\n" + "="*80)

def print_policy_comparison(comparison: Dict[str, Any]):
    """Print policy version comparison results"""
    print("\n" + "="*80)
    print("📊 POLICY VERSION COMPARISON")
    print("="*80)
    
    if 'error' in comparison:
        print(f"❌ {comparison['error']}")
        return
    
    print(f"\n🆕 ADDED ACTIONS ({len(comparison['added_actions'])}):")    
    for action in comparison['added_actions']:
        print(f"   + {action}")
    
    print(f"\n🗑️ REMOVED ACTIONS ({len(comparison['removed_actions'])}):")    
    for action in comparison['removed_actions']:
        print(f"   - {action}")
    
    impact = comparison['impact_analysis']
    if impact['risk_increase']:
        print(f"\n⚠️ RISK INCREASE DETECTED:")
        print(f"   New blocking actions: {len(impact['new_blocks'])}")
        print(f"   Affected services: {', '.join(impact['affected_services'])}")
    else:
        print(f"\n✅ No significant risk increase detected")

def print_policy_conflicts(conflicts: List[Dict[str, Any]]):
    """Print policy conflict analysis"""
    print("\n" + "="*80)
    print("⚔️ POLICY CONFLICT ANALYSIS")
    print("="*80)
    
    if not conflicts:
        print("\n✅ No policy conflicts detected")
        return
    
    print(f"\n🚨 CONFLICTS DETECTED ({len(conflicts)}):")
    for conflict in conflicts:
        print(f"\n   Target: {conflict['target_id']}")
        print(f"   Type: {conflict['type']}")
        print(f"   Action: {conflict['action']}")
        print(f"   Conflicting Policies: {', '.join(conflict['conflicting_policies'])}")
        print(f"   Description: {conflict['description']}")

def print_access_trace(trace_result: Dict[str, Any]):
    """Print cross-account access trace"""
    print("\n" + "="*80)
    print("🔗 CROSS-ACCOUNT ACCESS TRACE")
    print("="*80)
    
    if 'error' in trace_result:
        print(f"❌ {trace_result['error']}")
        return
    
    print(f"\n📋 TRACE DETAILS:")
    print(f"   Source Account: {trace_result['source_account']}")
    print(f"   Target Account: {trace_result['target_account']}")
    print(f"   Action: {trace_result['action']}")
    
    status = "✅ ALLOWED" if trace_result['access_allowed'] else "❌ DENIED"
    print(f"   Result: {status}")
    
    print(f"\n🔍 TRACE STEPS:")
    for step in trace_result['trace_steps']:
        print(f"   {step}")
    
    if trace_result['blocking_policies']:
        print(f"\n🚫 BLOCKING POLICIES:")
        for policy in trace_result['blocking_policies']:
            print(f"   • {policy['policy_name']} (ID: {policy['policy_id']})")

def print_breakglass_validation(validation: Dict[str, Any]):
    """Print break-glass validation results"""
    print("\n" + "="*80)
    print("🚨 BREAK-GLASS ACCESS VALIDATION")
    print("="*80)
    
    if 'error' in validation:
        print(f"❌ {validation['error']}")
        return
    
    print(f"\n🔧 EMERGENCY ROLE: {validation['emergency_role']}")
    print(f"   Account: {validation['account_id']}")
    
    status_icon = "✅" if validation['overall_status'] == 'FUNCTIONAL' else "❌"
    print(f"   Status: {status_icon} {validation['overall_status']}")
    
    if validation['blocked_actions']:
        print(f"\n🚫 BLOCKED CRITICAL ACTIONS ({len(validation['blocked_actions'])}):")        
        for blocked in validation['blocked_actions']:
            print(f"   ❌ {blocked['action']}")
            print(f"      Blocked by: {', '.join(blocked['blocking_policies'])}")
    
    if validation['allowed_actions']:
        print(f"\n✅ ALLOWED ACTIONS ({len(validation['allowed_actions'])}):")        
        for action in validation['allowed_actions']:
            print(f"   ✅ {action}")
    
    if validation['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in validation['recommendations']:
            print(f"   • {rec}")

def print_api_simulation(simulation: Dict[str, Any]):
    """Print API call simulation results"""
    print("\n" + "="*80)
    print("🧪 API CALL SIMULATION")
    print("="*80)
    
    if 'error' in simulation:
        print(f"❌ {simulation['error']}")
        return
    
    print(f"\n📋 SIMULATION DETAILS:")
    print(f"   Account: {simulation['account_id']}")
    print(f"   Action: {simulation['action']}")
    print(f"   Resource: {simulation['resource']}")
    
    result_icon = "✅" if simulation['result'] == 'ALLOWED' else "❌"
    print(f"   Result: {result_icon} {simulation['result']}")
    
    print(f"\n🔍 EVALUATION STEPS:")
    for step in simulation['evaluation_steps']:
        print(f"   {step}")
    
    if simulation['blocking_policies']:
        print(f"\n🚫 BLOCKING POLICIES:")
        for policy in simulation['blocking_policies']:
            print(f"   • {policy['policy_name']} (ID: {policy['policy_id']})")

def print_compliance_mapping(compliance: Dict[str, Any]):
    """Print compliance framework mapping"""
    print("\n" + "="*80)
    print("📋 COMPLIANCE FRAMEWORK MAPPING")
    print("="*80)
    
    summary = compliance['summary']
    print(f"\n📊 SUMMARY:")
    print(f"   Total Mapped Policies: {summary['total_mapped_policies']}")
    
    print(f"\n📈 COMPLIANCE COVERAGE:")
    for framework, coverage in summary['compliance_coverage'].items():
        print(f"   {framework}: {coverage['covered']}/{coverage['total']} ({coverage['percentage']}%)")
    
    # Show detailed mappings
    for framework in ['SOC2', 'PCI_DSS', 'NIST']:
        if framework in compliance:
            print(f"\n🏛️ {framework} MAPPING:")
            for control, details in compliance[framework].items():
                mapped_count = len(details['mapped_policies'])
                status = "✅" if mapped_count > 0 else "❌"
                print(f"   {status} {control}: {details['requirement']} ({mapped_count} policies)")
                if mapped_count > 0 and mapped_count <= 3:
                    for policy in details['mapped_policies']:
                        print(f"      • {policy}")
                elif mapped_count > 3:
                    print(f"      • {details['mapped_policies'][0]} and {mapped_count-1} others...")

def export_blocking_csv(blocking_report: Dict[str, Any], filename: str):
    """Export blocking report to CSV file"""
    import csv
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Type', 'Target_ID', 'Policy_Name', 'Policy_ID', 'Action', 'Impact', 'Severity'])
            
            # Write critical blocks
            for block in blocking_report['critical_blocks']:
                writer.writerow([
                    block['target_type'],
                    block['target_id'],
                    block['policy_name'],
                    block.get('policy_id', 'Unknown'),
                    block['action'],
                    block['impact'],
                    'CRITICAL'
                ])
            
            # Write account impacts
            for account_id, blocks in blocking_report['account_impacts'].items():
                for block in blocks:
                    writer.writerow([
                        'ACCOUNT',
                        account_id,
                        block.get('policy_name', 'Unknown'),
                        block.get('policy_id', 'Unknown'),
                        block['action'],
                        block['impact'],
                        block['severity']
                    ])
            
            # Write OU impacts
            for ou_id, blocks in blocking_report['ou_impacts'].items():
                for block in blocks:
                    writer.writerow([
                        'OU',
                        ou_id,
                        block.get('policy_name', 'Unknown'),
                        block.get('policy_id', 'Unknown'),
                        block['action'],
                        block['impact'],
                        block['severity']
                    ])
        
        print(f"\n💾 Blocking report exported to CSV: {filename}")
        
    except Exception as e:
        print(f"❌ Failed to export CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description='SCP Analysis Tool')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--role-arn', help='IAM role ARN to assume')
    parser.add_argument('--blocking-report-only', action='store_true', help='Generate only blocking report')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--export-csv', help='Export blocking report to CSV file')
    parser.add_argument('--detect-drift', help='Compare against baseline policies file')
    parser.add_argument('--check-resource', help='Analyze impact on specific resource ARN')
    parser.add_argument('--service-analysis', help='Deep dive on specific services (comma-separated)')
    parser.add_argument('--suggest-least-privilege', help='Suggest optimizations for account ID')
    parser.add_argument('--region-analysis', help='Analyze region restrictions (comma-separated regions)')
    parser.add_argument('--condition-analysis', action='store_true', help='Analyze time/IP/MFA conditions')
    parser.add_argument('--inheritance-chain', help='Show SCP inheritance for account ID')
    parser.add_argument('--security-coverage', action='store_true', help='Check security service protection')
    parser.add_argument('--unused-policies', action='store_true', help='Detect unused/ineffective policies')
    parser.add_argument('--policy-complexity', action='store_true', help='Analyze policy size and complexity')
    parser.add_argument('--simulate-action', help='Simulate API call: account_id,action,resource (e.g., 123456789012,s3:GetObject,arn:aws:s3:::bucket/*)')
    parser.add_argument('--what-if-policy', help='Test policy impact before deployment (JSON file or string)')
    parser.add_argument('--what-if-target', help='Target for what-if analysis (account_id or ou_id)')
    parser.add_argument('--permission-test', help='Test specific permission: account_id,action (e.g., 123456789012,ec2:RunInstances)')
    
    args = parser.parse_args()
    
    print("🚀 SCP Analysis Tool Starting...")
    print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    session = setup_session(args)
    analyzer = SCPAnalyzer(session)
    
    print("\n📋 Getting organization information...")
    org_info = analyzer.get_organization_info()
    if not org_info:
        print("❌ Failed to get organization info. Check permissions.")
        sys.exit(1)
    
    print(f"   Organization ID: {org_info['organization']['Id']}")
    print(f"   Total Accounts: {org_info['total_accounts']}")
    
    print("\n📜 Retrieving SCP policies...")
    policies = analyzer.get_all_policies()
    print(f"   Found {len(policies)} SCP policies")
    
    if args.blocking_report_only:
        print_blocking_report(analyzer)
        
        # Export to JSON if requested
        if args.export_json:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'organization_id': org_info['organization']['Id'],
                'total_accounts': org_info['total_accounts'],
                'total_policies': len(policies),
                'blocking_report': analyzer.generate_simple_blocking_report()
            }
            
            with open(args.export_json, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"\n💾 Results exported to: {args.export_json}")
        
        # Export to CSV if requested
        if args.export_csv:
            export_blocking_csv(analyzer.generate_simple_blocking_report(), args.export_csv)
    
    # Critical use cases
    if args.detect_drift:
        print("\n🔍 Policy drift detection...")
        try:
            with open(args.detect_drift, 'r') as f:
                baseline = json.load(f)
            current_names = {p['name'] for p in policies}
            baseline_names = {p['name'] for p in baseline}
            added = len(current_names - baseline_names)
            removed = len(baseline_names - current_names)
            print(f"➕ Added: {added} | ➖ Removed: {removed}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if args.check_resource:
        print(f"\n🎯 DETAILED RESOURCE ANALYSIS: {args.check_resource}")
        try:
            parts = args.check_resource.split(':')
            if len(parts) >= 3:
                service = parts[2]
                resource_name = parts[5] if len(parts) > 5 else '*'
                
                print(f"\n📋 RESOURCE DETAILS:")
                print(f"   Service: {service}")
                print(f"   Resource: {resource_name}")
                print(f"   Full ARN: {args.check_resource}")
                
                # Get detailed blocking analysis
                service_blocks = {}
                resource_specific_blocks = {}
                
                for policy in policies:
                    blocks = analyzer._extract_blocking_actions(policy)
                    policy_service_blocks = []
                    policy_resource_blocks = []
                    
                    for block in blocks:
                        action = block.get('action', '')
                        if action.startswith(f'{service}:'):
                            policy_service_blocks.append(action)
                            
                            # Check for resource-specific blocks
                            if resource_name != '*' and ('*' in resource_name or resource_name in action):
                                policy_resource_blocks.append(action)
                    
                    if policy_service_blocks:
                        service_blocks[policy['name']] = {
                            'policy_id': policy['id'],
                            'actions': policy_service_blocks,
                            'targets': policy.get('targets', [])
                        }
                    
                    if policy_resource_blocks:
                        resource_specific_blocks[policy['name']] = {
                            'policy_id': policy['id'],
                            'actions': policy_resource_blocks,
                            'targets': policy.get('targets', [])
                        }
                
                total_blocks = sum(len(details['actions']) for details in service_blocks.values())
                print(f"\n🔒 SERVICE BLOCKING SUMMARY:")
                print(f"   Total {service} blocking rules: {total_blocks}")
                print(f"   Policies with {service} blocks: {len(service_blocks)}")
                
                if service_blocks:
                    print(f"\n📊 POLICIES BLOCKING {service.upper()} SERVICE:")
                    for policy_name, details in service_blocks.items():
                        policy_id_short = details['policy_id'][:8] + "..."
                        print(f"\n   • {policy_name} ({policy_id_short})")
                        print(f"     Actions blocked: {len(details['actions'])}")
                        
                        # Show all blocked actions
                        for action in details['actions']:
                            severity = "🔴" if action.endswith(':*') or action == '*' else "🟡" if 'Delete' in action or 'Terminate' in action else "🟠"
                            print(f"       {severity} {action}")
                        
                        # Show targets
                        if details['targets']:
                            print(f"     Applied to:")
                            for target in details['targets']:
                                target_type = target.get('Type', 'Unknown')
                                target_id = target.get('TargetId', 'Unknown')
                                print(f"       - {target_type}: {target_id}")
                
                # Resource-specific analysis
                if resource_name != '*':
                    print(f"\n🎯 RESOURCE-SPECIFIC ANALYSIS:")
                    if resource_specific_blocks:
                        print(f"   Policies potentially affecting {resource_name}:")
                        for policy_name, details in resource_specific_blocks.items():
                            print(f"     • {policy_name}: {len(details['actions'])} relevant actions")
                    else:
                        print(f"   No policies specifically target pattern: {resource_name}")
                
                # Impact assessment
                print(f"\n⚠️  IMPACT ASSESSMENT:")
                critical_actions = [action for details in service_blocks.values() for action in details['actions'] 
                                  if action.endswith(':*') or action == '*']
                destructive_actions = [action for details in service_blocks.values() for action in details['actions'] 
                                     if any(word in action for word in ['Delete', 'Terminate', 'Remove', 'Destroy'])]
                
                if critical_actions:
                    print(f"   🔴 Critical blocks (wildcards): {len(critical_actions)}")
                    for action in critical_actions:
                        print(f"     - {action}")
                        
                
                if destructive_actions:
                    print(f"   🟡 Destructive actions blocked: {len(destructive_actions)}")
                    for action in destructive_actions:
                        print(f"     - {action}")
                        
                
                # Recommendations
                print(f"\n💡 RECOMMENDATIONS:")
                if total_blocks > 20:
                    print(f"   • High number of {service} blocks ({total_blocks}) - review for over-restriction")
                if critical_actions:
                    print(f"   • {len(critical_actions)} wildcard blocks detected - ensure they're intentional")
                if len(service_blocks) > 5:
                    print(f"   • Multiple policies ({len(service_blocks)}) block {service} - consider consolidation")
                if not service_blocks:
                    print(f"   • No SCP restrictions found for {service} service")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if args.service_analysis:
        print(f"\n📊 DETAILED SERVICE ANALYSIS: {args.service_analysis}")
        print("="*80)
        try:
            services = [s.strip() for s in args.service_analysis.split(',')]
            org_info = analyzer.get_organization_info()
            
            for service in services:
                print(f"\n🔒 {service.upper()} SERVICE ANALYSIS")
                print("-" * 50)
                
                # Debug: Ensure we're processing this service
                print(f"Processing service: {service}")
                
                # Collect detailed service data
                service_data = {
                    'policies': {},
                    'accounts_affected': set(),
                    'ous_affected': set(),
                    'total_blocks': 0,
                    'critical_blocks': 0,
                    'actions': set()
                }
                
                for policy in policies:
                    blocks = analyzer._extract_blocking_actions(policy)
                    policy_service_blocks = []
                    
                    for block in blocks:
                        action = block.get('action', '')
                        if action.startswith(f'{service}:'):
                            policy_service_blocks.append(block)
                            service_data['actions'].add(action)
                            service_data['total_blocks'] += 1
                            if block.get('severity') == 'CRITICAL':
                                service_data['critical_blocks'] += 1
                    
                    if policy_service_blocks:
                        service_data['policies'][policy['name']] = {
                            'policy_id': policy['id'],
                            'blocks': policy_service_blocks,
                            'targets': policy.get('targets', []),
                            'aws_managed': policy.get('aws_managed', False)
                        }
                        
                        # Track affected accounts and OUs
                        for target in policy.get('targets', []):
                            if target.get('Type') == 'ACCOUNT':
                                service_data['accounts_affected'].add(target.get('TargetId'))
                            elif target.get('Type') == 'ORGANIZATIONAL_UNIT':
                                service_data['ous_affected'].add(target.get('TargetId'))
                
                # Print summary
                print(f"📋 SUMMARY:")
                print(f"   Total blocking rules: {service_data['total_blocks']}")
                print(f"   Critical blocks: {service_data['critical_blocks']}")
                print(f"   Policies with {service} blocks: {len(service_data['policies'])}")
                print(f"   Unique actions blocked: {len(service_data['actions'])}")
                print(f"   Accounts affected: {len(service_data['accounts_affected'])}")
                print(f"   OUs affected: {len(service_data['ous_affected'])}")
                
                if service_data['policies']:
                    print(f"\n📊 POLICIES BLOCKING {service.upper()}:")
                    
                    for policy_name, policy_info in service_data['policies'].items():
                        policy_id_short = policy_info['policy_id'][:8] + "..."
                        aws_managed_indicator = " (AWS Managed)" if policy_info['aws_managed'] else ""
                        
                        print(f"\n   • {policy_name} ({policy_id_short}){aws_managed_indicator}")
                        print(f"     Blocks: {len(policy_info['blocks'])}")
                        
                        # Show all blocked actions with severity
                        for block in policy_info['blocks']:
                            action = block.get('action', 'Unknown')
                            severity = block.get('severity', 'UNKNOWN')
                            severity_icon = {
                                'CRITICAL': '🔴',
                                'HIGH': '🟡', 
                                'MEDIUM': '🟠',
                                'LOW': '🟢'
                            }.get(severity, '⚪')
                            
                            print(f"       {severity_icon} {action} ({severity})")
                        
                        # Show targets with account names
                        if policy_info['targets']:
                            print(f"     Applied to:")
                            for target in policy_info['targets']:
                                target_type = target.get('Type', 'Unknown')
                                target_id = target.get('TargetId', 'Unknown')
                                
                                # Get account name if it's an account
                                if target_type == 'ACCOUNT':
                                    account_name = 'Unknown'
                                    for account in org_info.get('accounts', []):
                                        if account['Id'] == target_id:
                                            account_name = account['Name']
                                            break
                                    print(f"       - {target_type}: {account_name} ({target_id})")
                                else:
                                    print(f"       - {target_type}: {target_id}")
                
                # Show most critical actions
                if service_data['actions']:
                    critical_actions = [action for action in service_data['actions'] 
                                      if action.endswith(':*') or action == '*']
                    destructive_actions = [action for action in service_data['actions'] 
                                         if any(word in action for word in ['Delete', 'Terminate', 'Remove', 'Destroy'])]
                    
                    print(f"\n⚠️  IMPACT ANALYSIS:")
                    if critical_actions:
                        print(f"   🔴 Critical wildcard blocks: {len(critical_actions)}")
                        for action in critical_actions:
                            print(f"     - {action}")
                    
                    if destructive_actions:
                        print(f"   🟡 Destructive actions blocked: {len(destructive_actions)}")
                        for action in destructive_actions:
                            print(f"     - {action}")
                
                # Recommendations
                print(f"\n💡 RECOMMENDATIONS:")
                if service_data['total_blocks'] > 20:
                    print(f"   • High number of {service} blocks ({service_data['total_blocks']}) - review for over-restriction")
                if service_data['critical_blocks'] > 0:
                    print(f"   • {service_data['critical_blocks']} critical blocks detected - ensure they're intentional")
                if len(service_data['policies']) > 5:
                    print(f"   • Multiple policies ({len(service_data['policies'])}) block {service} - consider consolidation")
                if service_data['total_blocks'] == 0:
                    print(f"   • No SCP restrictions found for {service} service")
                else:
                    print(f"   • Analysis complete for {service} service")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if args.suggest_least_privilege:
        print(f"\n💡 LEAST PRIVILEGE ANALYSIS FOR ACCOUNT: {args.suggest_least_privilege}")
        print("="*80)
        try:
            account_id = args.suggest_least_privilege
            org_info = analyzer.get_organization_info()
            
            # Find account name
            account_name = "Unknown Account"
            for account in org_info.get('accounts', []):
                if account['Id'] == account_id:
                    account_name = account['Name']
                    break
            
            print(f"\n📋 ACCOUNT DETAILS:")
            print(f"   Account ID: {account_id}")
            print(f"   Account Name: {account_name}")
            
            # Collect all policies affecting this account
            affecting_policies = []
            direct_policies = []
            inherited_policies = []
            
            for policy in policies:
                affects_account = False
                is_direct = False
                
                for target in policy.get('targets', []):
                    if target.get('TargetId') == account_id and target.get('Type') == 'ACCOUNT':
                        affects_account = True
                        is_direct = True
                        break
                    elif target.get('Type') in ['ORGANIZATIONAL_UNIT', 'ROOT']:
                        # Assume OU/Root policies affect this account (simplified)
                        affects_account = True
                        break
                
                if affects_account:
                    affecting_policies.append(policy)
                    if is_direct:
                        direct_policies.append(policy)
                    else:
                        inherited_policies.append(policy)
            
            print(f"\n📊 POLICY SUMMARY:")
            print(f"   Total policies affecting account: {len(affecting_policies)}")
            print(f"   Direct policies: {len(direct_policies)}")
            print(f"   Inherited policies: {len(inherited_policies)}")
            
            # Analyze all blocks for this account
            all_blocks = {}
            policy_overlap = {}
            service_blocks = {}
            
            for policy in affecting_policies:
                blocks = analyzer._extract_blocking_actions(policy)
                for block in blocks:
                    action = block.get('action', '')
                    service = action.split(':')[0] if ':' in action else 'unknown'
                    
                    # Track which policies block each action
                    if action not in all_blocks:
                        all_blocks[action] = []
                    all_blocks[action].append({
                        'policy_name': policy['name'],
                        'policy_id': policy['id'],
                        'severity': block.get('severity', 'UNKNOWN'),
                        'direct': policy in direct_policies
                    })
                    
                    # Track service-level blocks
                    if service not in service_blocks:
                        service_blocks[service] = []
                    service_blocks[service].append(action)
            
            # Find redundant blocks
            redundant_actions = {action: policies for action, policies in all_blocks.items() if len(policies) > 1}
            
            print(f"\n🔄 REDUNDANCY ANALYSIS:")
            print(f"   Total unique actions blocked: {len(all_blocks)}")
            print(f"   Redundantly blocked actions: {len(redundant_actions)}")
            print(f"   Services affected: {len(service_blocks)}")
            
            if redundant_actions:
                print(f"\n🔄 REDUNDANT BLOCKS (Actions blocked by multiple policies):")
                for action, policy_list in list(redundant_actions.items())[:]:
                    severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟡', 'MEDIUM': '🟠', 'LOW': '🟢'}
                    severity = policy_list[0]['severity']
                    icon = severity_icons.get(severity, '⚪')
                    
                    print(f"   {icon} {action} ({severity})")
                    print(f"     Blocked by {len(policy_list)} policies:")
                    for policy_info in policy_list:
                        policy_type = "Direct" if policy_info['direct'] else "Inherited"
                        policy_id_short = policy_info['policy_id'][:8] + "..."
                        print(f"       • {policy_info['policy_name']} ({policy_id_short}) - {policy_type}")
                    print()
                
            
            # Service-level analysis
            print(f"\n📊 SERVICE-LEVEL IMPACT:")
            for service, actions in sorted(service_blocks.items(), key=lambda x: len(x[1]), reverse=True):
                unique_actions = len(set(actions))
                total_blocks = len(actions)
                
                print(f"   🔒 {service}: {unique_actions} unique actions, {total_blocks} total blocks")
                
                # Show most critical actions for this service
                service_actions = [(action, all_blocks[action]) for action in set(actions)]
                critical_actions = [action for action, policies in service_actions 
                                  if any(p['severity'] == 'CRITICAL' for p in policies)]
                
                if critical_actions:
                    print(f"     🔴 Critical actions: {', '.join(critical_actions[:])}")
            
            # Optimization recommendations
            print(f"\n💡 LEAST PRIVILEGE RECOMMENDATIONS:")
            
            if len(redundant_actions) > 5:
                print(f"   🔄 HIGH REDUNDANCY DETECTED:")
                print(f"     • {len(redundant_actions)} actions are blocked by multiple policies")
                print(f"     • Consider consolidating policies to reduce complexity")
                print(f"     • Review if all blocking policies are necessary")
            
            if len(affecting_policies) > 10:
                print(f"   📋 POLICY COMPLEXITY:")
                print(f"     • {len(affecting_policies)} policies affect this account")
                print(f"     • Consider consolidating similar policies")
                print(f"     • Review inherited vs direct policy necessity")
            
            # Check for overly broad blocks - ALWAYS SHOW SECTION
            wildcard_actions = [action for action in all_blocks.keys() 
                              if action.endswith(':*') or action == '*']
            
            print(f"   🔴 OVERLY BROAD RESTRICTIONS:")
            if wildcard_actions:
                print(f"     • {len(wildcard_actions)} wildcard blocks detected")
                print(f"     • Consider more specific action restrictions")
                print(f"     • Wildcard actions found:")
                for action in wildcard_actions:
                    # Find which policies have this wildcard
                    policies_with_wildcard = [p['policy_name'] for p in all_blocks[action]]
                    print(f"       - {action} (blocked by: {', '.join(policies_with_wildcard)})")
            else:
                print(f"     ✅ No wildcard blocks detected")
                print(f"     • All {len(all_blocks)} actions use specific permissions")
                print(f"     • This follows least privilege principles")
                
                # Check for other broad patterns
                broad_patterns = []
                for action in all_blocks.keys():
                    if any(pattern in action.lower() for pattern in ['delete*', 'create*', 'put*', 'get*']):
                        broad_patterns.append(action)
                
                if broad_patterns:
                    print(f"     ⚠️  Found {len(broad_patterns)} potentially broad patterns:")
                    for pattern in broad_patterns:
                        print(f"       - {pattern}")
            
            # Service-specific recommendations
            high_impact_services = [service for service, actions in service_blocks.items() 
                                  if len(set(actions)) > 10]
            if high_impact_services:
                print(f"   ⚠️  HIGH-IMPACT SERVICES:")
                for service in high_impact_services[:]:
                    unique_count = len(set(service_blocks[service]))
                    print(f"     • {service}: {unique_count} unique actions blocked")
                    print(f"       Consider if all restrictions are necessary")
            
            # Unused policy detection
            unused_policies = [p for p in affecting_policies 
                             if not analyzer._extract_blocking_actions(p)]
            if unused_policies:
                print(f"   🗑️ UNUSED POLICIES:")
                print(f"     • {len(unused_policies)} policies have no blocking effect")
                for policy in unused_policies[:]:
                    print(f"       - {policy['name']} ({policy['id'][:8]}...)")
            
            if not redundant_actions and len(affecting_policies) <= 5:
                print(f"   ✅ WELL-OPTIMIZED:")
                print(f"     • No redundant blocks detected")
                print(f"     • Reasonable number of policies ({len(affecting_policies)})")
                print(f"     • Account appears to follow least privilege principles")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Additional critical features
    if args.region_analysis:
        print(f"\n🌍 REGION ANALYSIS: {args.region_analysis}")
        print("="*50)
        try:
            requested_regions = [r.strip() for r in args.region_analysis.split(',')]
            
            region_policies = []
            blocked_regions = set()
            allowed_regions = set()
            
            for policy in policies:
                if not isinstance(policy, dict) or 'content' not in policy:
                    continue
                    
                policy_content = policy['content']
                if not isinstance(policy_content, dict):
                    continue
                    
                statements = policy_content.get('Statement', [])
                if not isinstance(statements, list):
                    continue
                
                for statement in statements:
                    if not isinstance(statement, dict):
                        continue
                        
                    conditions = statement.get('Condition', {})
                    if not isinstance(conditions, dict):
                        continue
                    
                    # Check for region conditions
                    has_region_condition = False
                    for condition_type, condition_values in conditions.items():
                        if isinstance(condition_values, dict):
                            for key, values in condition_values.items():
                                if 'aws:RequestedRegion' in key:
                                    has_region_condition = True
                                    if isinstance(values, str):
                                        values = [values]
                                    elif isinstance(values, list):
                                        pass
                                    else:
                                        continue
                                    
                                    effect = statement.get('Effect', '')
                                    if effect == 'Deny':
                                        blocked_regions.update(values)
                                    elif effect == 'Allow':
                                        allowed_regions.update(values)
                                    
                                    region_policies.append({
                                        'policy_name': policy['name'],
                                        'policy_id': policy['id'],
                                        'effect': effect,
                                        'regions': values,
                                        'condition_type': condition_type
                                    })
            
            print(f"\n📊 REGION ANALYSIS SUMMARY:")
            print(f"   Policies with region conditions: {len(region_policies)}")
            print(f"   Blocked regions found: {len(blocked_regions)}")
            print(f"   Allowed regions found: {len(allowed_regions)}")
            
            if region_policies:
                print(f"\n🌍 REGION-RESTRICTED POLICIES:")
                for policy_info in region_policies:
                    effect_icon = "🚫" if policy_info['effect'] == 'Deny' else "✅"
                    policy_id_short = policy_info['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {policy_info['policy_name']} ({policy_id_short})")
                    print(f"     Effect: {policy_info['effect']}")
                    print(f"     Regions: {', '.join(policy_info['regions'])}")
                    print(f"     Condition: {policy_info['condition_type']}")
                    print()
            
            if blocked_regions:
                print(f"\n🚫 BLOCKED REGIONS ({len(blocked_regions)}):")
                for region in sorted(blocked_regions):
                    status = "🎯" if region in requested_regions else "📍"
                    print(f"   {status} {region}")
            
            if allowed_regions:
                print(f"\n✅ EXPLICITLY ALLOWED REGIONS ({len(allowed_regions)}):")
                for region in sorted(allowed_regions):
                    status = "🎯" if region in requested_regions else "📍"
                    print(f"   {status} {region}")
            
            # Analysis for requested regions
            print(f"\n🎯 ANALYSIS FOR REQUESTED REGIONS:")
            for region in requested_regions:
                if region in blocked_regions:
                    print(f"   🚫 {region}: BLOCKED by SCP policies")
                elif region in allowed_regions:
                    print(f"   ✅ {region}: EXPLICITLY ALLOWED by SCP policies")
                else:
                    print(f"   ⚪ {region}: No specific SCP restrictions found")
            
            if not region_policies:
                print(f"\n💡 RECOMMENDATIONS:")
                print(f"   • No region-based SCP restrictions found")
                print(f"   • Consider adding region restrictions for compliance")
                print(f"   • All regions are currently accessible unless restricted by other policies")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    if args.condition_analysis:
        print("\n⏰ CONDITION ANALYSIS")
        print("="*50)
        try:
            time_conditions = []
            ip_conditions = []
            mfa_conditions = []
            region_conditions = []
            other_conditions = []
            
            for policy in policies:
                if not isinstance(policy, dict) or 'content' not in policy:
                    continue
                    
                policy_content = policy['content']
                if not isinstance(policy_content, dict):
                    continue
                    
                statements = policy_content.get('Statement', [])
                if not isinstance(statements, list):
                    continue
                
                for statement in statements:
                    if not isinstance(statement, dict):
                        continue
                        
                    conditions = statement.get('Condition', {})
                    if not isinstance(conditions, dict):
                        continue
                    
                    # Analyze each condition
                    for condition_type, condition_values in conditions.items():
                        if not isinstance(condition_values, dict):
                            continue
                            
                        condition_info = {
                            'policy_name': policy['name'],
                            'policy_id': policy['id'],
                            'condition_type': condition_type,
                            'condition_values': condition_values,
                            'effect': statement.get('Effect', 'Unknown')
                        }
                        
                        # Categorize conditions
                        if 'Date' in condition_type:
                            time_conditions.append(condition_info)
                        elif 'IpAddress' in condition_type or 'NotIpAddress' in condition_type:
                            ip_conditions.append(condition_info)
                        elif any('aws:MultiFactorAuthPresent' in str(v) for v in condition_values.values()):
                            mfa_conditions.append(condition_info)
                        elif any('aws:RequestedRegion' in str(v) for v in condition_values.keys()):
                            region_conditions.append(condition_info)
                        else:
                            other_conditions.append(condition_info)
            
            print(f"\n📊 CONDITION SUMMARY:")
            print(f"   Time-based conditions: {len(time_conditions)}")
            print(f"   IP-based conditions: {len(ip_conditions)}")
            print(f"   MFA conditions: {len(mfa_conditions)}")
            print(f"   Region conditions: {len(region_conditions)}")
            print(f"   Other conditions: {len(other_conditions)}")
            
            # Time-based conditions
            if time_conditions:
                print(f"\n⏰ TIME-BASED CONDITIONS ({len(time_conditions)}):")
                for condition in time_conditions:
                    effect_icon = "🚫" if condition['effect'] == 'Deny' else "✅"
                    policy_id_short = condition['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {condition['policy_name']} ({policy_id_short})")
                    print(f"     Type: {condition['condition_type']}")
                    print(f"     Effect: {condition['effect']}")
                    for key, value in condition['condition_values'].items():
                        print(f"     {key}: {value}")
                    print()
            
            # IP-based conditions
            if ip_conditions:
                print(f"\n🌐 IP-BASED CONDITIONS ({len(ip_conditions)}):")
                for condition in ip_conditions:
                    effect_icon = "🚫" if condition['effect'] == 'Deny' else "✅"
                    policy_id_short = condition['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {condition['policy_name']} ({policy_id_short})")
                    print(f"     Type: {condition['condition_type']}")
                    print(f"     Effect: {condition['effect']}")
                    for key, value in condition['condition_values'].items():
                        print(f"     {key}: {value}")
                    print()
            
            # MFA conditions
            if mfa_conditions:
                print(f"\n🔐 MFA CONDITIONS ({len(mfa_conditions)}):")
                for condition in mfa_conditions:
                    effect_icon = "🚫" if condition['effect'] == 'Deny' else "✅"
                    policy_id_short = condition['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {condition['policy_name']} ({policy_id_short})")
                    print(f"     Type: {condition['condition_type']}")
                    print(f"     Effect: {condition['effect']}")
                    for key, value in condition['condition_values'].items():
                        print(f"     {key}: {value}")
                    print()
            
            # Region conditions
            if region_conditions:
                print(f"\n🌍 REGION CONDITIONS ({len(region_conditions)}):")
                for condition in region_conditions:
                    effect_icon = "🚫" if condition['effect'] == 'Deny' else "✅"
                    policy_id_short = condition['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {condition['policy_name']} ({policy_id_short})")
                    print(f"     Type: {condition['condition_type']}")
                    print(f"     Effect: {condition['effect']}")
                    for key, value in condition['condition_values'].items():
                        print(f"     {key}: {value}")
                    print()
            
            # Other conditions
            if other_conditions:
                print(f"\n🔧 OTHER CONDITIONS ({len(other_conditions)}):")
                for condition in other_conditions:
                    effect_icon = "🚫" if condition['effect'] == 'Deny' else "✅"
                    policy_id_short = condition['policy_id'][:8] + "..."
                    print(f"   {effect_icon} {condition['policy_name']} ({policy_id_short})")
                    print(f"     Type: {condition['condition_type']}")
                    print(f"     Effect: {condition['effect']}")
                    for key, value in condition['condition_values'].items():
                        print(f"     {key}: {value}")
                    print()
            
            # Summary and recommendations
            total_conditions = len(time_conditions) + len(ip_conditions) + len(mfa_conditions) + len(region_conditions) + len(other_conditions)
            
            if total_conditions == 0:
                print(f"\n💡 RECOMMENDATIONS:")
                print(f"   • No conditional restrictions found in SCP policies")
                print(f"   • Consider adding time-based restrictions for enhanced security")
                print(f"   • Consider adding IP-based restrictions for location control")
                print(f"   • Consider adding MFA requirements for sensitive operations")
            else:
                print(f"\n💡 ANALYSIS:")
                print(f"   • Total conditional policies: {total_conditions}")
                if len(time_conditions) > 0:
                    print(f"   • Time-based controls are in place")
                if len(ip_conditions) > 0:
                    print(f"   • IP-based controls are in place")
                if len(mfa_conditions) > 0:
                    print(f"   • MFA requirements are enforced")
                if len(region_conditions) > 0:
                    print(f"   • Regional restrictions are active")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    if args.inheritance_chain:
        print(f"\n🔗 INHERITANCE CHAIN ANALYSIS FOR: {args.inheritance_chain}")
        print("="*70)
        try:
            account_id = args.inheritance_chain
            org_info = analyzer.get_organization_info()
            
            # Find account details
            account_name = "Unknown Account"
            account_email = "Unknown"
            account_status = "Unknown"
            
            for account in org_info.get('accounts', []):
                if account['Id'] == account_id:
                    account_name = account['Name']
                    account_email = account['Email']
                    account_status = account['Status']
                    break
            
            print(f"\n📋 ACCOUNT DETAILS:")
            print(f"   Account ID: {account_id}")
            print(f"   Account Name: {account_name}")
            print(f"   Email: {account_email}")
            print(f"   Status: {account_status}")
            
            # Find direct policies (attached directly to account)
            direct_policies = []
            inherited_policies = []
            root_policies = []
            ou_policies = []
            
            for policy in policies:
                policy_targets = policy.get('targets', [])
                is_direct = False
                is_inherited = False
                
                for target in policy_targets:
                    target_type = target.get('Type', '')
                    target_id = target.get('TargetId', '')
                    
                    if target_type == 'ACCOUNT' and target_id == account_id:
                        is_direct = True
                        direct_policies.append({
                            'policy_name': policy['name'],
                            'policy_id': policy['id'],
                            'aws_managed': policy.get('aws_managed', False),
                            'description': policy.get('description', ''),
                            'blocks': len(analyzer._extract_blocking_actions(policy)),
                            'source_type': 'DIRECT',
                            'source': 'Direct to Account'
                        })
                    elif target_type == 'ROOT':
                        is_inherited = True
                        root_policies.append({
                            'policy_name': policy['name'],
                            'policy_id': policy['id'],
                            'aws_managed': policy.get('aws_managed', False),
                            'description': policy.get('description', ''),
                            'blocks': len(analyzer._extract_blocking_actions(policy)),
                            'source': 'Organization Root',
                            'source_type': 'ROOT'
                        })
                    elif target_type == 'ORGANIZATIONAL_UNIT':
                        is_inherited = True
                        ou_policies.append({
                            'policy_name': policy['name'],
                            'policy_id': policy['id'],
                            'aws_managed': policy.get('aws_managed', False),
                            'description': policy.get('description', ''),
                            'blocks': len(analyzer._extract_blocking_actions(policy)),
                            'source': f'OU: {target_id}',
                            'ou_id': target_id,
                            'source_type': 'OU'
                        })
                
                if is_inherited and not is_direct:
                    inherited_policies.append(policy)
            
            # Summary
            total_policies = len(direct_policies) + len(root_policies) + len(ou_policies)
            total_blocks = sum(p['blocks'] for p in direct_policies) + sum(p['blocks'] for p in root_policies) + sum(p['blocks'] for p in ou_policies)
            
            print(f"\n📊 INHERITANCE SUMMARY:")
            print(f"   Total policies affecting account: {total_policies}")
            print(f"   Direct policies: {len(direct_policies)}")
            print(f"   Root-level policies: {len(root_policies)}")
            print(f"   OU-level policies: {len(ou_policies)}")
            print(f"   Total blocking rules: {total_blocks}")
            
            # Direct policies
            if direct_policies:
                print(f"\n🎯 DIRECT POLICIES ({len(direct_policies)}):")
                print("   (Policies attached directly to this account)")
                for policy in direct_policies:
                    policy_id_short = policy['policy_id'][:8] + "..."
                    aws_managed_indicator = " (AWS Managed)" if policy['aws_managed'] else ""
                    print(f"\n   • {policy['policy_name']} ({policy_id_short}){aws_managed_indicator}")
                    print(f"     Blocking rules: {policy['blocks']}")
                    if policy['description']:
                        print(f"     Description: {policy['description']}")
            else:
                print(f"\n🎯 DIRECT POLICIES (0):")
                print("   No policies are directly attached to this account")
            
            # Root policies
            if root_policies:
                print(f"\n🌳 ROOT-LEVEL POLICIES ({len(root_policies)}):")
                print("   (Policies inherited from Organization Root)")
                for policy in root_policies:
                    policy_id_short = policy['policy_id'][:8] + "..."
                    aws_managed_indicator = " (AWS Managed)" if policy['aws_managed'] else ""
                    print(f"\n   • {policy['policy_name']} ({policy_id_short}){aws_managed_indicator}")
                    print(f"     Source: {policy['source']}")
                    print(f"     Blocking rules: {policy['blocks']}")
                    if policy['description']:
                        print(f"     Description: {policy['description']}")
            
            # OU policies
            if ou_policies:
                print(f"\n🏢 OU-LEVEL POLICIES ({len(ou_policies)}):")
                print("   (Policies inherited from Organizational Units)")
                
                # Group by OU
                ou_groups = {}
                for policy in ou_policies:
                    ou_id = policy['ou_id']
                    if ou_id not in ou_groups:
                        ou_groups[ou_id] = []
                    ou_groups[ou_id].append(policy)
                
                for ou_id, ou_policy_list in ou_groups.items():
                    print(f"\n   📁 From OU: {ou_id}")
                    for policy in ou_policy_list:
                        policy_id_short = policy['policy_id'][:8] + "..."
                        aws_managed_indicator = " (AWS Managed)" if policy['aws_managed'] else ""
                        print(f"     • {policy['policy_name']} ({policy_id_short}){aws_managed_indicator}")
                        print(f"       Blocking rules: {policy['blocks']}")
                        if policy['description']:
                            print(f"       Description: {policy['description']}")
            
            # Policy effectiveness analysis
            print(f"\n📈 POLICY EFFECTIVENESS:")
            effective_policies = [p for p in direct_policies + root_policies + ou_policies if p['blocks'] > 0]
            ineffective_policies = [p for p in direct_policies + root_policies + ou_policies if p['blocks'] == 0]
            
            print(f"   Effective policies (with blocks): {len(effective_policies)}")
            print(f"   Ineffective policies (no blocks): {len(ineffective_policies)}")
            
            if ineffective_policies:
                print(f"\n⚠️  INEFFECTIVE POLICIES:")
                print("   (Policies with no blocking rules - consider removing)")
                
                # Group ineffective policies by source for clarity
                direct_ineffective = [p for p in ineffective_policies if p.get('source_type') == 'DIRECT']
                root_ineffective = [p for p in ineffective_policies if p.get('source_type') == 'ROOT']
                ou_ineffective = [p for p in ineffective_policies if p.get('source_type') == 'OU']
                
                if direct_ineffective:
                    print(f"\n     📍 DIRECT (attached to account):")
                    for policy in direct_ineffective:
                        policy_id_short = policy['policy_id'][:8] + "..."
                        aws_managed = " (AWS Managed)" if policy.get('aws_managed') else ""
                        print(f"       • {policy['policy_name']} ({policy_id_short}){aws_managed}")
                
                if root_ineffective:
                    print(f"\n     🌳 ROOT-LEVEL (inherited from Organization Root):")
                    for policy in root_ineffective:
                        policy_id_short = policy['policy_id'][:8] + "..."
                        aws_managed = " (AWS Managed)" if policy.get('aws_managed') else ""
                        print(f"       • {policy['policy_name']} ({policy_id_short}){aws_managed}")
                
                if ou_ineffective:
                    print(f"\n     🏢 OU-LEVEL (inherited from OUs):")
                    # Group by OU for better clarity
                    ou_groups = {}
                    for policy in ou_ineffective:
                        ou_source = policy.get('source', 'Unknown OU')
                        if ou_source not in ou_groups:
                            ou_groups[ou_source] = []
                        ou_groups[ou_source].append(policy)
                    
                    for ou_source, ou_policies in ou_groups.items():
                        print(f"       📁 From {ou_source}:")
                        for policy in ou_policies:
                            policy_id_short = policy['policy_id'][:8] + "..."
                            aws_managed = " (AWS Managed)" if policy.get('aws_managed') else ""
                            print(f"         • {policy['policy_name']} ({policy_id_short}){aws_managed}")
            
            # Service impact analysis
            service_impacts = {}
            for policy_data in direct_policies + root_policies + ou_policies:
                # Get the full policy object
                full_policy = next((p for p in policies if p['id'] == policy_data['policy_id']), None)
                if full_policy:
                    blocks = analyzer._extract_blocking_actions(full_policy)
                    for block in blocks:
                        action = block.get('action', '')
                        if ':' in action:
                            service = action.split(':')[0]
                            if service not in service_impacts:
                                service_impacts[service] = 0
                            service_impacts[service] += 1
            
            if service_impacts:
                print(f"\n🔒 SERVICE IMPACT SUMMARY:")
                sorted_services = sorted(service_impacts.items(), key=lambda x: x[1], reverse=True)
                for service, count in sorted_services:
                    print(f"   {service}: {count} blocking rules")
            
            # Recommendations
            print(f"\n💡 RECOMMENDATIONS:")
            if len(direct_policies) == 0:
                print(f"   • Account relies entirely on inherited policies")
                print(f"   • Consider if account-specific policies are needed")
            
            if len(ineffective_policies) > 0:
                print(f"   • {len(ineffective_policies)} policies have no blocking effect")
                print(f"   • Review and consider removing ineffective policies")
            
            if total_policies > 10:
                print(f"   • High number of policies ({total_policies}) affecting this account")
                print(f"   • Consider policy consolidation to reduce complexity")
            
            if total_blocks > 50:
                print(f"   • High number of blocking rules ({total_blocks})")
                print(f"   • Review for potential over-restriction")
            
            if total_policies == 0:
                print(f"   • No SCP policies affect this account")
                print(f"   • Account has full AWS service access (subject to IAM policies)")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    if args.security_coverage:
        print("\n🛡️ Security coverage analysis...")
        try:
            coverage_data = analyzer.analyze_security_coverage()
            protected_count = len(coverage_data['protected_services'])
            unprotected_count = len(coverage_data['unprotected_services'])
            total_services = protected_count + unprotected_count
            
            print(f"🔒 Protected security services: {protected_count}/{total_services}")
            
            if coverage_data['protected_services']:
                print(f"\n✅ PROTECTED SERVICES ({protected_count}):")
                for service, policies in coverage_data['protected_services'].items():
                    print(f"  🛡️ {service}: Protected by {len(policies)} policies")
                    for policy in policies:  # Show ALL policies
                        print(f"    • {policy}")
            
            if coverage_data['unprotected_services']:
                print(f"\n❌ UNPROTECTED SERVICES ({unprotected_count}):")
                for service in coverage_data['unprotected_services']:
                    print(f"  ⚠️ {service}: Can be disabled/deleted")
            
            if coverage_data['recommendations']:
                print(f"\n💡 RECOMMENDATIONS:")
                for rec in coverage_data['recommendations']:
                    print(f"  • {rec}")
            
            if args.export_json:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'organization_id': org_info['organization']['Id'],
                    'total_policies': len(policies),
                    'security_coverage': coverage_data
                }
                with open(args.export_json, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                print(f"\n💾 Security coverage exported to: {args.export_json}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if args.unused_policies:
        print("\n🗑️ Unused policy detection...")
        try:
            unused_data = analyzer.detect_unused_policies()
            print(f"🗑️ Unused: {len(unused_data['unused_policies'])} | ⚠️ Ineffective: {len(unused_data['ineffective_policies'])}")
            
            if unused_data['unused_policies']:
                print(f"\n🗑️ UNUSED POLICIES ({len(unused_data['unused_policies'])}):")                
                for policy in unused_data['unused_policies'][:]:
                    print(f"  • {policy['policy_name']} (ID: {policy['policy_id']})")
                    print(f"    Reason: {policy['reason']}")
                if len(unused_data['unused_policies']) > 10:
                    pass
                    
            
            if unused_data['ineffective_policies']:
                print(f"\n⚠️ INEFFECTIVE POLICIES ({len(unused_data['ineffective_policies'])}):")                
                for policy in unused_data['ineffective_policies'][:]:
                    print(f"  • {policy['policy_name']} (ID: {policy['policy_id']})")
                    print(f"    Reason: {policy['reason']}")
                if len(unused_data['ineffective_policies']) > 10:
                    pass
                    
            
            if args.export_json:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'organization_id': org_info['organization']['Id'],
                    'total_policies': len(policies),
                    'unused_analysis': unused_data
                }
                with open(args.export_json, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                print(f"\n💾 Unused policies exported to: {args.export_json}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if args.policy_complexity:
        print("\n📏 POLICY COMPLEXITY ANALYSIS")
        print("="*50)
        try:
            complexity_data = analyzer.analyze_policy_complexity()
            
            print(f"\n📊 SUMMARY:")
            print(f"   Total policies analyzed: {len(policies)}")
            print(f"   Large policies (>4000 chars): {len(complexity_data['large_policies'])}")
            print(f"   Complex policies (>10 statements): {len(complexity_data['complex_policies'])}")
            print(f"   Total size across all policies: {complexity_data['total_size']:,} characters")
            print(f"   Average policy size: {complexity_data['total_size'] // len(policies) if policies else 0:,} characters")
            
            # Show large policies
            if complexity_data['large_policies']:
                print(f"\n📏 LARGE POLICIES ({len(complexity_data['large_policies'])}):")                
                for policy in complexity_data['large_policies']:
                    print(f"   📄 {policy['policy_name']}")
                    print(f"      Size: {policy['size']:,} characters")
                    print(f"      Statements: {policy['statements']}")
                    if policy['size'] > 4500:
                        print(f"      ⚠️  Approaching AWS limit (5120 chars)")
                    print()
            
            # Show complex policies
            if complexity_data['complex_policies']:
                print(f"\n🔀 COMPLEX POLICIES ({len(complexity_data['complex_policies'])}):")                
                for policy in complexity_data['complex_policies']:
                    print(f"   📋 {policy['policy_name']}")
                    print(f"      Statements: {policy['statements']}")
                    print(f"      Size: {policy['size']:,} characters")
                    if policy['statements'] > 20:
                        print(f"      ⚠️  Very complex - consider splitting")
                    print()
            
            # Show size warnings
            if complexity_data['size_warnings']:
                print(f"\n⚠️  SIZE WARNINGS ({len(complexity_data['size_warnings'])}):")                
                for warning in complexity_data['size_warnings']:
                    print(f"   🚨 {warning}")
            
            # Recommendations
            print(f"\n💡 RECOMMENDATIONS:")
            if len(complexity_data['large_policies']) > 0:
                print(f"   • {len(complexity_data['large_policies'])} policies are approaching size limits")
                print(f"   • Consider breaking large policies into smaller, focused policies")
            
            if len(complexity_data['complex_policies']) > 0:
                print(f"   • {len(complexity_data['complex_policies'])} policies have many statements")
                print(f"   • Complex policies are harder to maintain and troubleshoot")
            
            if complexity_data['total_size'] > 100000:
                print(f"   • Total policy size is {complexity_data['total_size']:,} characters")
                print(f"   • Consider policy consolidation and cleanup")
            
            if not complexity_data['large_policies'] and not complexity_data['complex_policies']:
                print(f"   ✅ All policies are within reasonable size and complexity limits")
                print(f"   ✅ No immediate optimization needed")
            
            if args.export_json:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'organization_id': org_info['organization']['Id'],
                    'total_policies': len(policies),
                    'complexity_analysis': complexity_data
                }
                with open(args.export_json, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                print(f"\n💾 Complexity analysis exported to: {args.export_json}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # 🧪 SIMULATION AND WHAT-IF ANALYSIS
    if args.simulate_action:
        print("\n🧪 API CALL SIMULATION")
        print("="*50)
        try:
            parts = args.simulate_action.split(',')
            if len(parts) >= 2:
                account_id = parts[0].strip()
                action = parts[1].strip()
                resource = parts[2].strip() if len(parts) > 2 else '*'
                
                simulation = analyzer.simulate_api_call(account_id, action, resource)
                print_api_simulation(simulation)
            else:
                print("❌ Invalid format. Use: account_id,action,resource")
        except Exception as e:
            print(f"❌ Simulation error: {e}")
    
    if args.what_if_policy:
        print("\n🔮 WHAT-IF POLICY ANALYSIS")
        print("="*50)
        try:
            target = args.what_if_target or "simulation"
            
            # Load policy content
            if args.what_if_policy.endswith('.json') and os.path.exists(args.what_if_policy):
                with open(args.what_if_policy, 'r') as f:
                    policy_content = json.load(f)
            else:
                policy_content = json.loads(args.what_if_policy)
            
            # Simulate policy impact
            impact = analyzer.simulate_policy_impact(policy_content, target)
            
            print(f"\n📋 WHAT-IF ANALYSIS FOR: {target}")
            print(f"   Policy would create {impact['total_restrictions']} restrictions")
            
            if impact['potential_breaks']:
                print(f"\n⚠️  POTENTIAL SERVICE IMPACTS:")
                for break_item in impact['potential_breaks']:
                    severity = "🔴" if "all" in break_item['impact'].lower() else "🟡"
                    print(f"   {severity} {break_item['action']}")
                    print(f"      Impact: {break_item['impact']}")
                    if break_item.get('condition'):
                        print(f"      Conditions: {break_item['condition']}")
            else:
                print("\n✅ No obvious service disruptions detected")
                
        except Exception as e:
            print(f"❌ What-if analysis error: {e}")
    
    if args.permission_test:
        print("\n🔍 PERMISSION TEST")
        print("="*50)
        try:
            parts = args.permission_test.split(',')
            if len(parts) >= 2:
                account_id = parts[0].strip()
                action = parts[1].strip()
                
                # Test the permission
                result = analyzer.troubleshoot_access_issue(account_id, action)
                
                print(f"\n📋 TESTING: {action} in account {account_id}")
                
                if result.get('is_likely_denied'):
                    print(f"   Result: ❌ LIKELY DENIED")
                    print(f"   Reason: SCP policies block this action")
                    
                    if result.get('denying_policies'):
                        print(f"\n🚫 BLOCKING POLICIES:")
                        for policy in result['denying_policies']:
                            print(f"     • {policy['policy_name']} (ID: {policy['policy_id']})")
                else:
                    print(f"   Result: ✅ LIKELY ALLOWED")
                    print(f"   Reason: No SCP restrictions found")
                
                print(f"\n📊 ANALYSIS DETAILS:")
                print(f"   Policies checked: {result.get('total_policies_checked', 0)}")
                print(f"   Blocking policies found: {len(result.get('denying_policies', []))}")
                
            else:
                print("❌ Invalid format. Use: account_id,action")
        except Exception as e:
            print(f"❌ Permission test error: {e}")

    print("\n✅ SCP Analysis Complete!")

# 🚀 Main execution block with comprehensive error handling
if __name__ == "__main__":
    try:
        main()  # Run the main analysis function
    except KeyboardInterrupt:
        # 👋 Handle graceful shutdown on Ctrl+C
        print("\n\n👋 Analysis interrupted by user")
        sys.exit(0)
    except NoCredentialsError:
        # 🔐 Handle missing AWS credentials
        print("❌ AWS credentials not found. Please configure credentials or use --profile/--role-arn")
        sys.exit(1)
    except Exception as e:
        # 🚨 Handle any other unexpected errors
        print(f"❌ Unexpected error: {e}")
        print("💡 Try running with --help for usage information")
        sys.exit(1)
