#!/bin/bash

# Test script for Report Agent
# This script demonstrates how to test the report_agent with sample data

set -e

echo "=== Report Agent Test Script ==="
echo ""

# Create test input
cat > /tmp/test_report_input.json << 'EOF'
{
  "aggregated_report": {
    "summary": {
      "total_findings": 5,
      "critical_findings": 2,
      "high_findings": 2,
      "medium_findings": 1,
      "low_findings": 0,
      "risk_score": 92.3
    },
    "findings": [
      {
        "id": "FIND-001",
        "title": "SQL Injection Vulnerability",
        "severity": "CRITICAL",
        "category": "SAST",
        "file_path": "src/database/queries.go",
        "line_number": 45,
        "priority": 1,
        "description": "User input is directly concatenated into SQL query without sanitization.",
        "owasp": ["A03:2021-Injection"],
        "cwe": ["CWE-89"]
      },
      {
        "id": "FIND-002",
        "title": "Hardcoded API Key",
        "severity": "CRITICAL",
        "category": "Secrets",
        "file_path": "config/api.go",
        "line_number": 12,
        "priority": 1,
        "description": "API key hardcoded in source code.",
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "cwe": ["CWE-798"]
      },
      {
        "id": "FIND-003",
        "title": "Vulnerable Dependency: lodash 4.17.15",
        "severity": "HIGH",
        "category": "SCA",
        "file_path": "package.json",
        "line_number": 23,
        "priority": 2,
        "description": "Prototype pollution vulnerability in lodash.",
        "owasp": ["A06:2021-Vulnerable and Outdated Components"],
        "cwe": ["CWE-1321"]
      }
    ],
    "statistics": {
      "by_category": {
        "SAST": 2,
        "SCA": 2,
        "Secrets": 1
      },
      "most_affected_files": [
        { "file_path": "src/database/queries.go", "count": 2 },
        { "file_path": "config/api.go", "count": 1 }
      ]
    }
  },
  "remediation_plans": [
    {
      "finding_id": "FIND-001",
      "primary_fix": {
        "command": "use_parameterized_query",
        "code_after": "db.Query(\"SELECT * FROM users WHERE id = ?\", userID)"
      }
    },
    {
      "finding_id": "FIND-002",
      "primary_fix": {
        "command": "use_env_var",
        "code_after": "apiKey := os.Getenv(\"API_KEY\")"
      }
    }
  ],
  "project_profile": {
    "metadata": {
      "project_name": "Example Web Application",
      "project_type": "web",
      "languages": ["Go", "JavaScript"],
      "frameworks": ["Gin", "React"]
    }
  },
  "project_context": {
    "domain": "e-commerce",
    "criticality": "high"
  },
  "config": {
    "formats": ["json", "html", "markdown"],
    "output_dir": "./test-reports",
    "include_executive_summary": true,
    "include_compliance_mapping": true,
    "include_visualizations": false,
    "theme": "light"
  }
}
EOF

echo "✓ Created test input file: /tmp/test_report_input.json"
echo ""

# Navigate to report_agent directory
cd "$(dirname "$0")/agents/report_agent"

echo "=== Testing Report Agent ==="
echo ""

# Test 1: Generate reports
echo "Test 1: Generating reports..."
cat /tmp/test_report_input.json | go run . generate_reports > /tmp/test_output.json

if [ $? -eq 0 ]; then
    echo "✓ Report generation successful"
    echo ""
    echo "Output summary:"
    cat /tmp/test_output.json | grep -A 5 '"summary"'
    echo ""
else
    echo "✗ Report generation failed"
    exit 1
fi

# Test 2: Check generated files
echo "Test 2: Checking generated report files..."
if [ -d "./test-reports" ]; then
    echo "✓ Output directory created"
    ls -lh ./test-reports/
    echo ""
else
    echo "✗ Output directory not found"
    exit 1
fi

# Test 3: Validate JSON output
echo "Test 3: Validating JSON structure..."
if command -v jq &> /dev/null; then
    cat /tmp/test_output.json | jq '.metadata.project_name' > /dev/null
    if [ $? -eq 0 ]; then
        echo "✓ JSON output is valid"
        echo ""
    else
        echo "✗ JSON output is invalid"
        exit 1
    fi
else
    echo "⚠ jq not installed, skipping JSON validation"
    echo ""
fi

# Test 4: Check Ollama integration
echo "Test 4: Checking Ollama integration..."
if grep -q "Executive Summary could not be generated" /tmp/test_output.json 2>/dev/null; then
    echo "⚠ Ollama not available (expected if not running)"
elif grep -q "executive_summary" /tmp/test_output.json 2>/dev/null; then
    echo "✓ Executive summary generated via Ollama"
else
    echo "⚠ Executive summary status unclear"
fi
echo ""

# Cleanup
echo "=== Cleanup ==="
rm -rf ./test-reports
rm /tmp/test_report_input.json
rm /tmp/test_output.json
echo "✓ Cleaned up test files"
echo ""

echo "=== All Tests Passed ==="
echo ""
echo "To run with Ollama:"
echo "  1. Start Ollama: ollama serve"
echo "  2. Pull model: ollama pull codellama"
echo "  3. Set env vars: export OLLAMA_URL=http://localhost:11434"
echo "  4. Run this script again"
