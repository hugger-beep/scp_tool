# SCP Analysis Tool - Technical Documentation

## Overview
The SCP Analysis Tool is a comprehensive Python-based utility for analyzing AWS Service Control Policies (SCPs) within AWS Organizations. It provides detailed insights into policy impacts, blocking patterns, and organizational security posture.

## What This Tool Does

### Core Functionality
1. **Policy Discovery & Parsing**
   - Retrieves all SCP policies from AWS Organizations
   - Parses policy JSON content and extracts deny statements
   - Maps policies to their organizational targets (OUs, accounts, root)
   - Handles AWS managed and custom policies

2. **Blocking Analysis**
   - Identifies which AWS services and actions are being blocked
   - Counts individual deny statements (not just policies)
   - Maps blocking rules to specific policies and targets
   - Categorizes blocks by severity (CRITICAL, HIGH, MEDIUM, LOW)

3. **Service Impact Assessment**
   - Groups blocked actions by AWS service (e.g., s3, iam, ec2)
   - Shows detailed breakdown of which policies block each service
   - Lists all specific actions being denied (no truncation)
   - Provides policy-to-action mapping for troubleshooting

4. **Account & OU Analysis**
   - Identifies accounts and OUs affected by SCP policies
   - Filters out accounts with zero blocking policies
   - Shows inheritance patterns and policy sources
   - Provides detailed policy-to-account mappings

5. **Risk Assessment**
   - Analyzes policies for potential service disruption
   - Identifies overly broad deny statements (wildcards)
   - Flags policies affecting critical services (IAM, STS, Organizations)
   - Provides risk severity ratings

## How It Works

### Data Collection Process
```
1. Connect to AWS Organizations API
2. List all SCP policies in the organization
3. For each policy:
   - Retrieve policy content (JSON)
   - Parse policy statements
   - Extract deny statements and actions
   - Get policy targets (OUs/accounts)
4. Build comprehensive data structure
5. Generate analysis reports
```

### Key Data Structures
- **Policies**: List of all SCP policies with content and targets
- **Blocking Report**: Service-grouped analysis of deny statements
- **Account Impacts**: Per-account breakdown of blocking policies
- **OU Impacts**: Per-OU breakdown of blocking policies

### Analysis Logic

#### Service Block Counting
```python
# "75 blocking rules" means:
# - 75 individual deny statements across all policies
# - NOT 75 policies
# - Each policy can contribute multiple deny statements
```

#### Severity Classification
- **CRITICAL**: Wildcards (`*`, `service:*`)
- **HIGH**: Critical services (iam:, sts:, organizations:)
- **MEDIUM**: Standard service actions
- **LOW**: Specific/limited actions

## What This Tool Will Do

### ✅ Capabilities
1. **Comprehensive SCP Discovery**
   - Lists all SCP policies in your organization
   - Shows policy content, targets, and AWS managed status
   - Handles pagination for large organizations

2. **Detailed Blocking Analysis**
   - Shows every blocked action without truncation
   - Groups actions by AWS service
   - Maps actions to specific policies
   - Provides policy ID and name for each block

3. **Account Impact Assessment**
   - Shows which accounts are affected by SCPs
   - Lists specific policies blocking each account
   - Shows all blocked actions per policy
   - Filters out accounts with no blocks

4. **Service Impact Breakdown**
   - Groups blocks by AWS service (s3, iam, ec2, etc.)
   - Shows which policies block each service
   - Lists all specific actions being blocked
   - No truncation - shows complete details

5. **Risk Analysis**
   - Identifies high-risk policies
   - Flags overly broad deny statements
   - Highlights critical service blocks
   - Provides severity ratings

6. **Export Capabilities**
   - JSON export for programmatic analysis
   - CSV export for spreadsheet analysis
   - Structured data for integration

7. **🧪 Real-time Simulation & Testing** ✅ **NEW**
   - API call simulation against SCP policies
   - What-if policy analysis before deployment
   - Permission testing and troubleshooting
   - Policy impact prediction

### 📊 Report Types
1. **Blocking Report** (`--blocking-report-only`)
   - Service-by-service breakdown
   - Policy-to-action mapping
   - Account impact analysis
   - Summary statistics

2. **Security Coverage** (`--security-coverage`)
   - Protected vs unprotected security services
   - Policy coverage analysis
   - Recommendations for gaps

3. **Unused Policies** (`--unused-policies`)
   - Policies with no targets
   - Policies with no deny statements
   - Optimization opportunities

4. **Policy Complexity** (`--policy-complexity`)
   - Large policies approaching AWS limits
   - Complex policies with many statements
   - Size warnings and recommendations

5. **🧪 Simulation & Testing** (`--simulate-action`, `--what-if-policy`, `--permission-test`)
   - Real-time API call simulation
   - What-if policy impact analysis
   - Permission validation and troubleshooting
   - Pre-deployment testing capabilities

## What This Tool Will NOT Do

### ❌ Limitations
1. **IAM Policy Analysis**
   - Does NOT analyze IAM policies (identity-based)
   - Only analyzes Service Control Policies (SCPs)
   - Cannot assess resource-based policies

2. **Cross-Account Role Analysis**
   - Does NOT analyze assume role permissions
   - Cannot trace complex cross-account access patterns
   - Limited to SCP policy evaluation

3. **Resource-Level Restrictions**
   - Does NOT analyze resource-specific conditions
   - Cannot evaluate complex policy conditions
   - Limited to action-level analysis

4. **Organizational Structure Changes**
   - Does NOT modify AWS Organizations structure
   - Cannot attach/detach policies
   - Read-only analysis tool

5. **Policy Content Modification**
   - Does NOT modify existing policies
   - Cannot create or update SCP policies
   - Analysis and reporting only

6. **Full AWS Authorization Simulation**
   - Does NOT simulate complete AWS authorization flow
   - Cannot evaluate IAM policies, resource policies, or session policies
   - Limited to SCP-level evaluation only
   - Does NOT make real AWS API calls

## Understanding the Output

### Service Block Count Explanation
```
🔒 config: 75 blocking rules (individual deny statements)
```
- **75**: Total number of individual deny statements affecting config service
- **NOT**: 75 different policies
- **Example**: One policy with `config:*` = 1 policy but many blocking rules

### Account Analysis
```
👤 ACCOUNTS WITH BLOCKS (3):
  🔐 Account 123456789012: 15 total blocks
     Blocking Policies:
       • PolicyName (p-abc123...) - 8 blocks
         - config:DeleteConfigRule
         - config:StopConfigurationRecorder
         - iam:DeleteRole
```
- Shows only accounts with actual blocking policies
- Lists all specific actions being blocked
- No truncation - complete details

### Summary Statistics
```
📋 Total Policies with Blocks: 12
   (Unique SCP policies that contain deny statements)
🎯 Unique Actions Blocked: 156
   (Distinct AWS actions being denied across all policies)
🏢 OUs Affected: 7
   (Organizational Units with SCP policies attached)
👤 Accounts Analyzed: 9
   (Total accounts in organization)
```

## Prerequisites

### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeOrganization",
                "organizations:ListAccounts",
                "organizations:ListRoots",
                "organizations:ListPolicies",
                "organizations:DescribePolicy",
                "organizations:ListTargetsForPolicy",
                "organizations:ListOrganizationalUnitsForParent",
                "organizations:ListAccountsForParent",
                "organizations:ListPoliciesForTarget"
            ],
            "Resource": "*"
        }
    ]
}
```

### Environment Requirements
- Python 3.7+
- boto3 library
- AWS credentials configured
- Access to AWS Organizations management account

## Usage Examples

### Basic Analysis
```bash
python3 scp_analysis.py --blocking-report-only
```

### Export Results
```bash
python3 scp_analysis.py --blocking-report-only --export-json results.json --export-csv blocking.csv
```

### Cross-Account Analysis
```bash
python3 scp_analysis.py --role-arn arn:aws:iam::MGMT-ACCOUNT:role/SCPAnalysisRole --blocking-report-only
```

### Security Coverage Check
```bash
python3 scp_analysis.py --security-coverage
```

### Complete Command Reference

#### Authentication Options
```bash
# Use specific AWS profile
python3 scp_analysis.py --profile my-profile --blocking-report-only

# Assume cross-account role
python3 scp_analysis.py --role-arn arn:aws:iam::123456789012:role/SCPRole --blocking-report-only
```

#### Analysis Commands
```bash
# Basic blocking analysis
python3 scp_analysis.py --blocking-report-only

# Service-specific analysis
python3 scp_analysis.py --service-analysis s3,iam,ec2

# Resource impact analysis
python3 scp_analysis.py --check-resource arn:aws:s3:::my-bucket

# Account inheritance analysis
python3 scp_analysis.py --inheritance-chain 123456789012

# Least privilege recommendations
python3 scp_analysis.py --suggest-least-privilege 123456789012

# Region restriction analysis
python3 scp_analysis.py --region-analysis us-east-1,eu-west-1

# Conditional policy analysis
python3 scp_analysis.py --condition-analysis

# Security service coverage
python3 scp_analysis.py --security-coverage

# Policy management
python3 scp_analysis.py --unused-policies
python3 scp_analysis.py --policy-complexity

# Policy drift detection
python3 scp_analysis.py --detect-drift baseline.json
```

#### Simulation & Testing
```bash
# API call simulation
python3 scp_analysis.py --simulate-action "123456789012,s3:GetObject,arn:aws:s3:::bucket/*"

# What-if policy analysis
python3 scp_analysis.py --what-if-policy policy.json --what-if-target 123456789012

# Permission testing
python3 scp_analysis.py --permission-test "123456789012,ec2:RunInstances"
```

#### Export Options
```bash
# Export to JSON
python3 scp_analysis.py --blocking-report-only --export-json results.json

# Export to CSV
python3 scp_analysis.py --blocking-report-only --export-csv blocking.csv

# Combined export
python3 scp_analysis.py --security-coverage --export-json security.json
```

### 🧪 NEW: Simulation & Testing Features

#### Real-time API Call Simulation (SCP-Level Only)
```bash
# Test if an API call would be blocked by SCPs (not a complete authorization check)
python3 scp_analysis.py --simulate-action "123456789012,s3:GetObject,arn:aws:s3:::prod-bucket/*"
```
**⚠️ Note**: This only checks SCP policies, not IAM policies or other authorization layers

#### What-If Policy Analysis
```bash
# Test policy impact before deployment
python3 scp_analysis.py --what-if-policy policy.json --what-if-target 123456789012

# Test policy from JSON string
python3 scp_analysis.py --what-if-policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}' --what-if-target ou-production
```

#### Permission Testing
```bash
# Test specific permission for troubleshooting
python3 scp_analysis.py --permission-test "123456789012,ec2:RunInstances"

# Cross-account role testing
python3 scp_analysis.py --permission-test "123456789012,sts:AssumeRole"
```

### 🔍 Advanced Analysis Features

#### Region Analysis
```bash
# Analyze region-based restrictions
python3 scp_analysis.py --region-analysis us-east-1,eu-west-1
```

#### Condition Analysis
```bash
# Analyze time/IP/MFA conditions in policies
python3 scp_analysis.py --condition-analysis
```

#### Inheritance Chain Analysis
```bash
# Show complete policy inheritance for an account
python3 scp_analysis.py --inheritance-chain 123456789012
```

#### Least Privilege Analysis
```bash
# Get optimization suggestions for an account
python3 scp_analysis.py --suggest-least-privilege 123456789012
```

#### Policy Management
```bash
# Detect unused or ineffective policies
python3 scp_analysis.py --unused-policies

# Analyze policy size and complexity
python3 scp_analysis.py --policy-complexity

# Check security service protection
python3 scp_analysis.py --security-coverage

# Detect policy drift (compare against baseline)
python3 scp_analysis.py --detect-drift baseline.json
```

#### Enhanced Resource Analysis
```bash
# Detailed resource impact analysis with policy breakdown
python3 scp_analysis.py --check-resource arn:aws:s3:::prod-*
```
**Output:**
```
🎯 DETAILED RESOURCE ANALYSIS: arn:aws:s3:::prod-*
📋 RESOURCE DETAILS:
   Service: s3
   Resource: prod-*
   Full ARN: arn:aws:s3:::prod-*

🔒 SERVICE BLOCKING SUMMARY:
   Total s3 blocking rules: 55
   Policies with s3 blocks: 8

📊 POLICIES BLOCKING S3 SERVICE:
   • deny-s3-production (p-abc123...)
     Actions blocked: 12
       🔴 s3:*
       🟡 s3:DeleteBucket
       🟠 s3:GetObject
     Applied to:
       - ORGANIZATIONAL_UNIT: ou-root-abc123
       - ACCOUNT: 123456789012

💡 RECOMMENDATIONS:
   • High number of s3 blocks (55) - review for over-restriction
   • 3 wildcard blocks detected - ensure they're intentional
```

## Troubleshooting

### Common Issues
1. **"Total Policies with Blocks: 0"**
   - All SCPs contain only Allow statements (unusual)
   - SCPs have no targets attached
   - Policy parsing issues
   - All policies are AWS managed defaults

2. **"No accounts have blocking policies"**
   - All policies are attached to OUs only
   - Policies have no deny statements
   - Account filtering is working correctly

3. **Permission Errors**
   - Ensure you're running from Organizations management account
   - Check IAM permissions listed above
   - Verify AWS credentials are configured

### Debug Information
The tool provides debug output when values are unexpectedly zero, helping identify configuration issues or policy problems.

### Performance Considerations
- Large organizations (100+ accounts) may take several minutes to analyze
- Policy retrieval is the most time-consuming operation
- Use `--export-json` to cache results for repeated analysis
- Cross-account role assumption adds authentication overhead

### Version Information
Author: Anon  
Version: 2.2 (Enhanced)  
Last Updated: 2025-01-29

## Integration

### JSON Export Structure
```json
{
    "timestamp": "2025-01-23T10:30:00",
    "organization_id": "o-example123",
    "total_policies": 57,
    "blocking_report": {
        "service_blocks": {...},
        "account_impacts": {...},
        "ou_impacts": {...}
    }
}
```

### CSV Export Format
```csv
Type,Target_ID,Policy_Name,Policy_ID,Action,Impact,Severity
ACCOUNT,123456789012,PolicyName,p-abc123,s3:DeleteBucket,Blocks s3:DeleteBucket,MEDIUM
```

## 🧪 Simulation & What-If Analysis

### Real-time Permission Testing
The tool now provides SCP-level simulation capabilities:

#### API Call Simulation
```bash
python3 scp_analysis.py --simulate-action "123456789012,s3:GetObject,arn:aws:s3:::bucket/*"
```
**Output:**
```
🧪 API CALL SIMULATION
📋 SIMULATION DETAILS:
   Account: 123456789012
   Action: s3:GetObject
   Resource: arn:aws:s3:::bucket/*
   Result: ❌ DENIED

🚫 BLOCKING POLICIES:
   • deny-s3-production (ID: p-abc123...)
   • restrict-s3-access (ID: p-def456...)
```

#### What-If Policy Analysis
```bash
python3 scp_analysis.py --what-if-policy new-policy.json --what-if-target 123456789012
```
**Output:**
```
🔮 WHAT-IF POLICY ANALYSIS
📋 WHAT-IF ANALYSIS FOR: 123456789012
   Policy would create 47 restrictions

⚠️  POTENTIAL SERVICE IMPACTS:
   🔴 s3:*
      Impact: Blocks all S3 operations (high risk)
   🟡 s3:DeleteBucket
      Impact: Cannot delete S3 buckets
```

#### Permission Testing
```bash
python3 scp_analysis.py --permission-test "123456789012,ec2:RunInstances"
```
**Output:**
```
🔍 PERMISSION TEST
📋 TESTING: ec2:RunInstances in account 123456789012
   Result: ❌ LIKELY DENIED
   Reason: SCP policies block this action

🚫 BLOCKING POLICIES:
     • deny-ec2-production (ID: p-xyz789...)
```

### Simulation Capabilities

#### ✅ What This DOES:
- **SCP-Level Simulation** - Tests against Service Control Policies
- **Policy Impact Prediction** - Shows what would break with new policies
- **Permission Troubleshooting** - Identifies SCP blocks for specific actions
- **What-If Analysis** - Tests policy changes before deployment
- **API Call Validation** - Predicts if actions would be blocked

#### ❌ What This DOES NOT:
- **Real AWS API Calls** - Does not make actual API requests
- **IAM Policy Evaluation** - Only considers SCPs, not identity-based policies
- **Resource Policy Analysis** - Does not evaluate bucket policies, etc.
- **Condition Context** - Cannot simulate time, IP, MFA conditions
- **Final Authorization** - AWS has many layers beyond SCPs

## 🎯 What API Call Simulation Actually Does

### **SCP-Level Evaluation Only**
When you run:
```bash
python3 scp_analysis.py --simulate-action "123456789012,s3:GetObject,arn:aws:s3:::prod-bucket/*"
```

**The tool performs these steps:**
1. **Finds all SCP policies** affecting account `123456789012`
2. **Checks each policy** for DENY statements that match `s3:GetObject`
3. **Evaluates wildcards** like `s3:*` or `*` that would block the action
4. **Reports the result** based on SCP evaluation only

### **What It Checks:**
- ✅ **Service Control Policies (SCPs)** - All deny statements
- ✅ **Policy inheritance** - Direct, OU-level, and Root-level policies
- ✅ **Action matching** - Exact matches and wildcard patterns
- ✅ **Resource patterns** - Basic resource ARN matching

### **What It Does NOT Check:**
- ❌ **IAM policies** (identity-based permissions)
- ❌ **Resource-based policies** (S3 bucket policies, etc.)
- ❌ **Session policies** or temporary credentials
- ❌ **Real AWS API calls** - No actual API requests made
- ❌ **Complex conditions** (time, IP, MFA requirements)
- ❌ **Cross-account trust relationships**

### **⚠️ Important Understanding:**

**If simulation shows ALLOWED:**
- ✅ **No SCPs block this action**
- ❓ **But the call might still fail** due to IAM policies, bucket policies, etc.

**If simulation shows DENIED:**
- ❌ **SCPs will definitely block this action**
- ❌ **The call will fail** regardless of other permissions

### **Use Cases:**
- ✅ **"Will this action be blocked by our SCPs?"**
- ✅ **"Are our SCPs too restrictive?"**
- ✅ **"Quick SCP troubleshooting"**
- ❌ **"Will this API call actually work?"** (too many other factors)

**Bottom line**: It's a **quick SCP-level check**, not a complete AWS authorization simulation.

## 📊 Command Line Arguments Reference

| Argument | Description | Example |
|----------|-------------|----------|
| `--profile` | AWS profile name | `--profile my-profile` |
| `--role-arn` | IAM role ARN to assume | `--role-arn arn:aws:iam::123:role/Role` |
| `--blocking-report-only` | Generate blocking analysis report | `--blocking-report-only` |
| `--export-json` | Export results to JSON file | `--export-json results.json` |
| `--export-csv` | Export blocking report to CSV | `--export-csv blocking.csv` |
| `--detect-drift` | Compare against baseline file | `--detect-drift baseline.json` |
| `--check-resource` | Analyze specific resource ARN | `--check-resource arn:aws:s3:::bucket` |
| `--service-analysis` | Deep dive on services | `--service-analysis s3,iam,ec2` |
| `--suggest-least-privilege` | Optimization for account | `--suggest-least-privilege 123456789012` |
| `--region-analysis` | Analyze region restrictions | `--region-analysis us-east-1,eu-west-1` |
| `--condition-analysis` | Analyze conditional policies | `--condition-analysis` |
| `--inheritance-chain` | Show policy inheritance | `--inheritance-chain 123456789012` |
| `--security-coverage` | Check security service protection | `--security-coverage` |
| `--unused-policies` | Detect unused/ineffective policies | `--unused-policies` |
| `--policy-complexity` | Analyze policy size/complexity | `--policy-complexity` |
| `--simulate-action` | Simulate API call | `--simulate-action "123,s3:GetObject,arn"` |
| `--what-if-policy` | Test policy impact | `--what-if-policy policy.json` |
| `--what-if-target` | Target for what-if analysis | `--what-if-target 123456789012` |
| `--permission-test` | Test specific permission | `--permission-test "123,ec2:RunInstances"` |ders SCPs, not identity-based policies
- **Resource Policy Analysis** - Does not evaluate bucket policies, etc.
- **Condition Context** - Cannot simulate time, IP, MFA conditions
- **Final Authorization** - AWS has many layers beyond SCPs

### Use Cases for Simulation

1. **Pre-deployment Testing**
   ```bash
   # Before applying a new SCP policy
   python3 scp_analysis.py --what-if-policy new-security-policy.json --what-if-target ou-production
   ```

2. **Troubleshooting Access Issues**
   ```bash
   # "Why can't I launch EC2 instances?"
   python3 scp_analysis.py --permission-test "123456789012,ec2:RunInstances"
   ```

3. **API Call Validation**
   ```bash
   # "Will this API call work?"
   python3 scp_analysis.py --simulate-action "123456789012,s3:PutObject,arn:aws:s3:::my-bucket/file.txt"
   ```

4. **Cross-Account Access Testing**
   ```bash
   # "Can I assume this role?"
   python3 scp_analysis.py --simulate-action "123456789012,sts:AssumeRole,arn:aws:iam::987654321098:role/CrossAccountRole"
   ```

## 🚀 Quick Start Guide

### 1. First Time Analysis
```bash
# Get overview of what's being blocked
python3 scp_analysis.py --blocking-report-only
```

### 2. Export for Team Review
```bash
# Generate reports for management
python3 scp_analysis.py --blocking-report-only --export-json results.json --export-csv blocking.csv
```

### 3. Troubleshoot Specific Issues
```bash
# Why can't I access this service?
python3 scp_analysis.py --service-analysis s3,iam

# What affects this account?
python3 scp_analysis.py --inheritance-chain 123456789012

# Test specific permission
python3 scp_analysis.py --permission-test "123456789012,s3:CreateBucket"
```

### 4. Security & Compliance
```bash
# Check security service protection
python3 scp_analysis.py --security-coverage

# Analyze regional restrictions
python3 scp_analysis.py --region-analysis us-east-1,eu-west-1

# Review conditional policies
python3 scp_analysis.py --condition-analysis
```

### 5. Policy Optimization
```bash
# Find unused policies
python3 scp_analysis.py --unused-policies

# Get optimization suggestions
python3 scp_analysis.py --suggest-least-privilege 123456789012

# Check policy complexity
python3 scp_analysis.py --policy-complexity
```
