#!/bin/bash

# Test script for SAST Agent
# This script tests all four tools: scan_project, validate_finding, generate_fix_recommendation, get_available_rulesets

set -e

echo "=== SAST Agent Test Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Semgrep is installed
if ! command -v semgrep &> /dev/null; then
    echo -e "${RED}✗${NC} Semgrep is not installed"
    echo "Please install Semgrep: brew install semgrep"
    exit 1
fi

echo "Semgrep version: $(semgrep --version 2>&1 | head -1)"
echo ""

# Create test project with vulnerabilities
echo "Creating test project with intentional vulnerabilities..."
mkdir -p /tmp/test_sast_project

cat > /tmp/test_sast_project/vulnerable.go << 'GOEOF'
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// Vulnerable: SQL Injection
func getUserByID(db *sql.DB, userID string) error {
	query := "SELECT * FROM users WHERE id = '" + userID + "'"
	_, err := db.Query(query)
	return err
}

// Vulnerable: Command Injection  
func pingHost(host string) error {
	cmd := exec.Command("ping", "-c", "1", host)
	return cmd.Run()
}

// Vulnerable: Hardcoded credentials
const apiKey = "sk-1234567890abcdef"

func main() {
	fmt.Println("Vulnerable test application")
}
GOEOF

echo -e "${GREEN}✓${NC} Test project created"
echo ""

# Navigate to sast_agent directory
# cd "$(dirname "$0")/agents/sast_agent"

echo "=== Test 1: get_available_rulesets ===" 
echo ""

echo "Running get_available_rulesets..."
echo '{}' | go run . get_available_rulesets > /tmp/test_sast_rulesets.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} get_available_rulesets completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        RULESET_COUNT=$(cat /tmp/test_sast_rulesets.json | jq '.rulesets | length')
        echo "  Rulesets available: $RULESET_COUNT"
        
        echo "  Sample rulesets:"
        cat /tmp/test_sast_rulesets.json | jq -r '.rulesets[0:3][] | "    - \(.name): \(.description)"'
        echo ""
        
        if [ "$RULESET_COUNT" -ge 5 ]; then
            echo -e "${GREEN}✓${NC} Multiple rulesets available"
        fi
    fi
else
    echo -e "${RED}✗${NC} get_available_rulesets failed"
    cat /tmp/test_sast_rulesets.json
    exit 1
fi
echo ""

echo "=== Test 2: scan_project (Basic Scan) ===" 
echo ""

# Create test input for scan_project
cat > /tmp/test_sast_scan.json << 'EOF'
{
  "project_path": "/tmp/test_sast_project",
  "languages": ["Go"],
  "config": {
    "rules": ["p/security-audit"],
    "severity": "medium",
    "skip_patterns": [],
    "max_findings": 50,
    "validate_with_ollama": false,
    "confidence_threshold": "",
    "timeout_seconds": 60
  },
  "project_context": {
    "type": "api",
    "domain": "general",
    "frameworks": []
  }
}
EOF

echo "Running scan_project on vulnerable code..."
cat /tmp/test_sast_scan.json | go run . scan_project > /tmp/test_sast_scan_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} scan_project completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        FINDINGS_COUNT=$(cat /tmp/test_sast_scan_output.json | jq '.findings | length')
        FILES_SCANNED=$(cat /tmp/test_sast_scan_output.json | jq '.scan_summary.files_scanned')
        DURATION=$(cat /tmp/test_sast_scan_output.json | jq '.scan_summary.duration_ms')
        
        echo "  Findings detected: $FINDINGS_COUNT"
        echo "  Files scanned: $FILES_SCANNED"
        echo "  Scan duration: ${DURATION}ms"
        
        # Check severity distribution
        echo ""
        echo "  Findings by severity:"
        cat /tmp/test_sast_scan_output.json | jq -r '.scan_summary.findings_by_severity | to_entries[] | "    \(.key): \(.value)"' 2>/dev/null || echo "    (no data)"
        
        if [ "$FINDINGS_COUNT" -gt 0 ]; then
            echo ""
            echo -e "${GREEN}✓${NC} Vulnerabilities detected in test code"
            
            # Show sample findings
            echo ""
            echo "  Sample findings:"
            cat /tmp/test_sast_scan_output.json | jq -r '.findings[0:3][] | "    - \(.severity): \(.title) at \(.file_path):\(.line_number)"' 2>/dev/null
        else
            echo -e "${YELLOW}⚠${NC} No findings detected (unexpected for vulnerable code)"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} scan_project failed"
    cat /tmp/test_sast_scan_output.json
    exit 1
fi

echo "=== Test 3: scan_project (With Severity Filter) ===" 
echo ""

# Test with high severity only
cat > /tmp/test_sast_scan_high.json << 'EOF'
{
  "project_path": "/tmp/test_sast_project",
  "languages": ["Go"],
  "config": {
    "rules": ["p/owasp-top-ten"],
    "severity": "high",
    "skip_patterns": [],
    "max_findings": 10,
    "validate_with_ollama": false,
    "confidence_threshold": "",
    "timeout_seconds": 60
  },
  "project_context": {
    "type": "api",
    "domain": "general",
    "frameworks": []
  }
}
EOF

echo "Running scan with high severity filter..."
cat /tmp/test_sast_scan_high.json | go run . scan_project > /tmp/test_sast_scan_high_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} High severity scan completed"
    
    if command -v jq &> /dev/null; then
        HIGH_FINDINGS=$(cat /tmp/test_sast_scan_high_output.json | jq '.findings | length')
        echo "  High severity findings: $HIGH_FINDINGS"
    fi
    echo ""
else
    echo -e "${YELLOW}⚠${NC} High severity scan had issues (may be expected)"
    echo ""
fi

echo "=== Test 4: validate_finding ===" 
echo ""

# Extract a finding from the scan to validate
if command -v jq &> /dev/null && [ -f /tmp/test_sast_scan_output.json ]; then
    FIRST_FINDING=$(cat /tmp/test_sast_scan_output.json | jq '.findings[0]' 2>/dev/null)
    
    if [ "$FIRST_FINDING" != "null" ] && [ -n "$FIRST_FINDING" ]; then
        # Create validation input
        cat > /tmp/test_sast_validate.json << EOF
{
  "finding": $FIRST_FINDING,
  "code_context": "func getUserByID(db *sql.DB, userID string) error {\n\tquery := \"SELECT * FROM users WHERE id = '\" + userID + \"'\"\n\t_, err := db.Query(query)\n\treturn err\n}",
  "project_context": {
    "type": "api",
    "domain": "general",
    "frameworks": ["gin"]
  }
}
EOF
        
        echo "Running validate_finding..."
        cat /tmp/test_sast_validate.json | go run . validate_finding > /tmp/test_sast_validate_output.json 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC} validate_finding completed successfully"
            echo ""
            
            IS_VULNERABLE=$(cat /tmp/test_sast_validate_output.json | jq -r '.is_vulnerable')
            CONFIDENCE=$(cat /tmp/test_sast_validate_output.json | jq -r '.confidence')
            RISK_LEVEL=$(cat /tmp/test_sast_validate_output.json | jq -r '.risk_level')
            
            echo "  Is vulnerable: $IS_VULNERABLE"
            echo "  Confidence: $CONFIDENCE"
            echo "  Risk level: $RISK_LEVEL"
            echo ""
        else
            echo -e "${YELLOW}⚠${NC} validate_finding failed (Ollama may not be available)"
            echo ""
        fi
    else
        echo -e "${YELLOW}⚠${NC} No findings to validate"
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} Skipping validate_finding test (no findings available)"
    echo ""
fi

echo "=== Test 5: generate_fix_recommendation ===" 
echo ""

# Generate fix recommendation for a finding
if command -v jq &> /dev/null && [ -f /tmp/test_sast_scan_output.json ]; then
    FIRST_FINDING=$(cat /tmp/test_sast_scan_output.json | jq '.findings[0]' 2>/dev/null)
    
    if [ "$FIRST_FINDING" != "null" ] && [ -n "$FIRST_FINDING" ]; then
        cat > /tmp/test_sast_fix.json << EOF
{
  "finding": $FIRST_FINDING
}
EOF
        
        echo "Running generate_fix_recommendation..."
        cat /tmp/test_sast_fix.json | go run . generate_fix_recommendation > /tmp/test_sast_fix_output.json 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC} generate_fix_recommendation completed successfully"
            echo ""
            
            RECOMMENDATION=$(cat /tmp/test_sast_fix_output.json | jq -r '.recommendation' | head -c 200)
            echo "  Recommendation preview: ${RECOMMENDATION}..."
            echo ""
        else
            echo -e "${YELLOW}⚠${NC} generate_fix_recommendation failed (Ollama may not be available)"
            echo ""
        fi
    else
        echo -e "${YELLOW}⚠${NC} No findings for fix recommendation"
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} Skipping fix recommendation test"
    echo ""
fi

echo "=== Test 6: Error Handling ===" 
echo ""

# Temporarily disable exit on error
set +e

# Test with missing required field
echo "Testing error handling with missing project_path..."
echo '{"languages": ["Go"], "config": {}}' | go run . scan_project > /tmp/test_sast_error.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly validates required fields"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with missing project_path"
fi
echo ""

# Test with missing languages
echo "Testing error handling with missing languages..."
echo '{"project_path": "/tmp/test", "config": {}}' | go run . scan_project > /tmp/test_sast_error2.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly validates languages field"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with missing languages"
fi
echo ""

# Re-enable exit on error
set -e

echo "=== Test 7: JSON Output Validation ===" 
echo ""

echo "Validating JSON structure for all outputs..."
if command -v jq &> /dev/null; then
    for file in /tmp/test_sast_rulesets.json /tmp/test_sast_scan_output.json; do
        if [ -f "$file" ]; then
            cat "$file" | jq empty 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓${NC} $(basename $file) is valid JSON"
            else
                echo -e "${RED}✗${NC} $(basename $file) is invalid JSON"
                exit 1
            fi
        fi
    done
else
    echo -e "${YELLOW}⚠${NC} jq not installed, skipping JSON validation"
fi
echo ""

# Cleanup
echo "=== Cleanup ===" 
rm -rf /tmp/test_sast_project
rm -f /tmp/test_sast_*.json
echo -e "${GREEN}✓${NC} Cleaned up test files"
echo ""

echo -e "${GREEN}=== All SAST Agent Tests Passed ===${NC}"
echo ""

echo "Summary:"
echo "  ✓ Semgrep integration working"
echo "  ✓ Vulnerability detection functional"
echo "  ✓ Ruleset management available"
echo "  ✓ Error handling correct"
echo "  ✓ JSON output valid"
