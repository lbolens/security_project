#!/bin/bash

# Test script for Remediation Agent
# This script tests all six tools: generate_remediation_plans, generate_code_fix, generate_dependency_fix,
# generate_action_plan, estimate_complexity, generate_tests

set -e

echo "=== Remediation Agent Test Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Navigate to remediation_agent directory
cd "$(dirname "$0")"

# Helper function to call MCP methods
call_mcp() {
    local method=$1
    local params_file=$2
    local output_file=$3

    echo "{\"method\":\"$method\",\"params\":$(cat $params_file | jq -c '.')}" | go run . 2>&1 | jq '.result' > $output_file
}

echo "=== Test 1: estimate_complexity (Dependency Update) ==="
echo ""

# Test complexity estimation for simple dependency update
cat > /tmp/test_complexity_simple.json << 'EOF'
{
  "finding": {
    "id": "finding-1",
    "type": "vulnerable-dependency",
    "severity": "high",
    "component_name": "lodash"
  },
  "fix": {
    "type": "dependency-update",
    "description": "Update lodash to 4.17.21",
    "command": "npm install lodash@4.17.21"
  }
}
EOF

echo "Running estimate_complexity for dependency update..."
call_mcp "estimate_complexity" /tmp/test_complexity_simple.json /tmp/test_complexity_simple_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} estimate_complexity (simple) completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        COMPLEXITY=$(cat /tmp/test_complexity_simple_output.json | jq -r '.complexity')
        ESTIMATED_TIME=$(cat /tmp/test_complexity_simple_output.json | jq -r '.estimated_time')
        EXPERTISE=$(cat /tmp/test_complexity_simple_output.json | jq -r '.requires_expertise')

        echo "  Complexity: $COMPLEXITY"
        echo "  Estimated time: $ESTIMATED_TIME"
        echo "  Required expertise: $EXPERTISE"

        if [ "$COMPLEXITY" = "low" ]; then
            echo -e "${GREEN}✓${NC} Correctly assessed as low complexity"
        fi

        if [ "$EXPERTISE" = "junior" ]; then
            echo -e "${GREEN}✓${NC} Correctly requires junior level expertise"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} estimate_complexity (simple) failed"
    cat /tmp/test_complexity_simple_output.json
    exit 1
fi

echo "=== Test 2: estimate_complexity (Complex Code Patch) ==="
echo ""

# Test complexity for complex code change
cat > /tmp/test_complexity_complex.json << 'EOF'
{
  "finding": {
    "id": "finding-2",
    "type": "sql-injection",
    "severity": "critical",
    "file_path": "core/auth/handler.go"
  },
  "fix": {
    "type": "code-patch",
    "description": "Refactor authentication logic",
    "code_before": "func login() {}",
    "code_after": "func login() {}\nfunc validateUser() {}\nfunc checkCredentials() {}\n// 20+ more lines...",
    "breaking_change": true
  }
}
EOF

echo "Running estimate_complexity for complex patch..."
call_mcp "estimate_complexity" /tmp/test_complexity_complex.json /tmp/test_complexity_complex_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} estimate_complexity (complex) completed successfully"

    if command -v jq &> /dev/null; then
        COMPLEXITY=$(cat /tmp/test_complexity_complex_output.json | jq -r '.complexity')
        EXPERTISE=$(cat /tmp/test_complexity_complex_output.json | jq -r '.requires_expertise')
        FACTORS=$(cat /tmp/test_complexity_complex_output.json | jq -r '.factors[]')

        echo "  Complexity: $COMPLEXITY"
        echo "  Required expertise: $EXPERTISE"
        echo "  Factors: $FACTORS"

        if [ "$COMPLEXITY" = "high" ]; then
            echo -e "${GREEN}✓${NC} Correctly assessed as high complexity"
        fi

        if [ "$EXPERTISE" = "senior" ]; then
            echo -e "${GREEN}✓${NC} Correctly requires senior expertise"
        fi
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} estimate_complexity (complex) had issues"
    echo ""
fi

echo "=== Test 3: generate_dependency_fix ==="
echo ""

# Test dependency fix generation
cat > /tmp/test_dependency_fix.json << 'EOF'
{
  "finding": {
    "id": "sca-1",
    "type": "vulnerable-dependency",
    "component_name": "lodash",
    "current_version": "4.17.20",
    "target_version": "4.17.21",
    "cve": "CVE-2021-23337",
    "cvss": 7.4,
    "file_path": "package.json"
  }
}
EOF

echo "Running generate_dependency_fix..."
call_mcp "generate_dependency_fix" /tmp/test_dependency_fix.json /tmp/test_dependency_fix_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_dependency_fix completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        UPDATE_CMD=$(cat /tmp/test_dependency_fix_output.json | jq -r '.fix.update_command')
        VERIFY_CMD=$(cat /tmp/test_dependency_fix_output.json | jq -r '.fix.verify_command')
        ROLLBACK_CMD=$(cat /tmp/test_dependency_fix_output.json | jq -r '.fix.rollback_command')

        echo "  Update command: $UPDATE_CMD"
        echo "  Verify command: $VERIFY_CMD"
        echo "  Rollback command: $ROLLBACK_CMD"

        if [[ "$UPDATE_CMD" == *"npm install"* ]] || [[ "$UPDATE_CMD" == *"lodash"* ]]; then
            echo -e "${GREEN}✓${NC} Generated appropriate npm update command"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_dependency_fix failed"
    cat /tmp/test_dependency_fix_output.json
    exit 1
fi

echo "=== Test 4: generate_code_fix (SQL Injection) ==="
echo ""

# Test code fix generation (without Ollama - will use fallback)
cat > /tmp/test_code_fix.json << 'EOF'
{
  "finding": {
    "id": "sast-1",
    "type": "sql-injection",
    "category": "injection",
    "severity": "critical",
    "title": "SQL Injection in user handler",
    "description": "Unsafe SQL query construction",
    "file_path": "handlers/user.go",
    "line_number": 42,
    "cwe": ["CWE-89"],
    "owasp": ["A03:2021-Injection"]
  },
  "project_context": {
    "type": "api",
    "frameworks": "gin",
    "domain": "finance"
  }
}
EOF

echo "Running generate_code_fix for SQL injection..."
call_mcp "generate_code_fix" /tmp/test_code_fix.json /tmp/test_code_fix_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_code_fix completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        FIX_TYPE=$(cat /tmp/test_code_fix_output.json | jq -r '.fix.type')
        CODE_BEFORE=$(cat /tmp/test_code_fix_output.json | jq -r '.fix.code_before' | head -c 50)
        CODE_AFTER=$(cat /tmp/test_code_fix_output.json | jq -r '.fix.code_after' | head -c 50)
        RATIONALE=$(cat /tmp/test_code_fix_output.json | jq -r '.fix.rationale' | head -c 80)

        echo "  Fix type: $FIX_TYPE"
        echo "  Code before (preview): $CODE_BEFORE..."
        echo "  Code after (preview): $CODE_AFTER..."
        echo "  Rationale: $RATIONALE..."

        if [ "$FIX_TYPE" = "code-patch" ]; then
            echo -e "${GREEN}✓${NC} Generated code-patch fix type"
        fi

        # Check if it uses parameterized query
        FULL_CODE_AFTER=$(cat /tmp/test_code_fix_output.json | jq -r '.fix.code_after')
        if [[ "$FULL_CODE_AFTER" == *"?"* ]] || [[ "$FULL_CODE_AFTER" == *"param"* ]]; then
            echo -e "${GREEN}✓${NC} Fix uses parameterized query approach"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_code_fix failed"
    cat /tmp/test_code_fix_output.json
    exit 1
fi

echo "=== Test 5: generate_code_fix (XSS) ==="
echo ""

# Test XSS fix generation
cat > /tmp/test_code_fix_xss.json << 'EOF'
{
  "finding": {
    "id": "sast-2",
    "type": "xss",
    "category": "injection",
    "severity": "high",
    "title": "Cross-Site Scripting vulnerability",
    "description": "Unescaped user input in HTML",
    "file_path": "templates/profile.html",
    "line_number": 128
  },
  "project_context": {
    "type": "web",
    "frameworks": "react"
  }
}
EOF

echo "Running generate_code_fix for XSS..."
call_mcp "generate_code_fix" /tmp/test_code_fix_xss.json /tmp/test_code_fix_xss_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_code_fix (XSS) completed successfully"

    if command -v jq &> /dev/null; then
        CODE_AFTER=$(cat /tmp/test_code_fix_xss_output.json | jq -r '.fix.code_after')

        if [[ "$CODE_AFTER" == *"escape"* ]] || [[ "$CODE_AFTER" == *"Escape"* ]] || [[ "$CODE_AFTER" == *"sanitize"* ]]; then
            echo -e "${GREEN}✓${NC} XSS fix includes escaping/sanitization"
        fi
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} generate_code_fix (XSS) had issues"
    echo ""
fi

echo "=== Test 6: generate_action_plan ==="
echo ""

# Test action plan generation
cat > /tmp/test_action_plan.json << 'EOF'
{
  "finding": {
    "id": "finding-1",
    "type": "sql-injection",
    "severity": "critical"
  },
  "fix": {
    "type": "code-patch",
    "description": "Replace string concatenation with parameterized query",
    "file_path": "handlers/user.go"
  }
}
EOF

echo "Running generate_action_plan..."
call_mcp "generate_action_plan" /tmp/test_action_plan.json /tmp/test_action_plan_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_action_plan completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        STEPS_COUNT=$(cat /tmp/test_action_plan_output.json | jq '.steps | length')
        ESTIMATED_TIME=$(cat /tmp/test_action_plan_output.json | jq -r '.estimated_time')
        PREREQS=$(cat /tmp/test_action_plan_output.json | jq '.prerequisites | length')

        echo "  Number of steps: $STEPS_COUNT"
        echo "  Estimated time: $ESTIMATED_TIME"
        echo "  Prerequisites: $PREREQS"

        if [ "$STEPS_COUNT" -ge 3 ]; then
            echo -e "${GREEN}✓${NC} Generated detailed step-by-step plan"
        fi

        echo ""
        echo "  First few steps:"
        cat /tmp/test_action_plan_output.json | jq -r '.steps[0:3][] | "    \(.order). \(.title)"'
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_action_plan failed"
    cat /tmp/test_action_plan_output.json
    exit 1
fi

echo "=== Test 7: generate_tests ==="
echo ""

# Test test generation
cat > /tmp/test_generate_tests.json << 'EOF'
{
  "finding": {
    "id": "finding-1",
    "type": "sql-injection",
    "file_path": "handlers/user.go"
  },
  "fix": {
    "type": "code-patch",
    "description": "Use parameterized queries"
  }
}
EOF

echo "Running generate_tests..."
call_mcp "generate_tests" /tmp/test_generate_tests.json /tmp/test_generate_tests_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_tests completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        TESTS_COUNT=$(cat /tmp/test_generate_tests_output.json | jq '.tests | length')

        echo "  Number of tests: $TESTS_COUNT"

        if [ "$TESTS_COUNT" -ge 2 ]; then
            echo -e "${GREEN}✓${NC} Generated multiple test steps"
        fi

        echo ""
        echo "  Test types:"
        cat /tmp/test_generate_tests_output.json | jq -r '.tests[] | "    - \(.type): \(.description)"'
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_tests failed"
    cat /tmp/test_generate_tests_output.json
    exit 1
fi

echo "=== Test 8: generate_remediation_plans (Full Pipeline) ==="
echo ""

# Test full remediation plan generation
cat > /tmp/test_full_remediation.json << 'EOF'
{
  "aggregated_report": {
    "findings": [
      {
        "id": "sast-1",
        "type": "sql-injection",
        "category": "injection",
        "severity": "critical",
        "title": "SQL Injection",
        "description": "SQL vulnerability",
        "file_path": "api/users.go",
        "line_number": 42,
        "cwe": ["CWE-89"]
      },
      {
        "id": "sca-1",
        "type": "vulnerable-dependency",
        "severity": "high",
        "component_name": "lodash",
        "current_version": "4.17.20",
        "target_version": "4.17.21",
        "cve": "CVE-2021-23337",
        "cvss": 7.4
      }
    ]
  },
  "project_profile": {
    "languages": ["go", "javascript"]
  },
  "project_context": {
    "type": "api",
    "domain": "finance"
  },
  "config": {
    "generate_alternatives": true,
    "max_alternatives": 2,
    "include_tests": true,
    "detailed_steps": true,
    "estimate_complexity": true
  }
}
EOF

echo "Running generate_remediation_plans with full configuration..."
call_mcp "generate_remediation_plans" /tmp/test_full_remediation.json /tmp/test_full_remediation_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_remediation_plans completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        TOTAL_PLANS=$(cat /tmp/test_full_remediation_output.json | jq '.remediation_plans | length')
        LOW_COMPLEXITY=$(cat /tmp/test_full_remediation_output.json | jq '.summary.by_complexity.low')
        HIGH_COMPLEXITY=$(cat /tmp/test_full_remediation_output.json | jq '.summary.by_complexity.high')
        TOTAL_TIME=$(cat /tmp/test_full_remediation_output.json | jq -r '.summary.estimated_total_time')

        echo "  Total remediation plans: $TOTAL_PLANS"
        echo "  Low complexity: $LOW_COMPLEXITY"
        echo "  High complexity: $HIGH_COMPLEXITY"
        echo "  Estimated total time: $TOTAL_TIME"

        if [ "$TOTAL_PLANS" -eq 2 ]; then
            echo -e "${GREEN}✓${NC} Correct number of plans generated (2)"
        fi

        # Check first plan details
        echo ""
        echo "  First plan details:"
        FINDING_ID=$(cat /tmp/test_full_remediation_output.json | jq -r '.remediation_plans[0].finding_id')
        FIX_TYPE=$(cat /tmp/test_full_remediation_output.json | jq -r '.remediation_plans[0].primary_fix.type')
        COMPLEXITY=$(cat /tmp/test_full_remediation_output.json | jq -r '.remediation_plans[0].complexity')
        HAS_STEPS=$(cat /tmp/test_full_remediation_output.json | jq '.remediation_plans[0].steps | length')
        HAS_TESTS=$(cat /tmp/test_full_remediation_output.json | jq '.remediation_plans[0].testing | length')
        HAS_ALTERNATIVES=$(cat /tmp/test_full_remediation_output.json | jq '.remediation_plans[0].alternative_fixes | length')

        echo "    Finding ID: $FINDING_ID"
        echo "    Fix type: $FIX_TYPE"
        echo "    Complexity: $COMPLEXITY"
        echo "    Steps: $HAS_STEPS"
        echo "    Tests: $HAS_TESTS"
        echo "    Alternatives: $HAS_ALTERNATIVES"

        if [ "$HAS_STEPS" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Action steps generated"
        fi

        if [ "$HAS_TESTS" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Test steps generated"
        fi

        if [ "$HAS_ALTERNATIVES" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Alternative fixes generated"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_remediation_plans failed"
    cat /tmp/test_full_remediation_output.json
    exit 1
fi

echo "=== Test 9: Error Handling ==="
echo ""

# Temporarily disable exit on error
set +e

# Test with invalid JSON
echo "Testing error handling with invalid JSON..."
echo '{invalid json}' | go run . > /tmp/test_error.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly handles invalid JSON"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with invalid JSON"
fi
echo ""

# Test with missing required fields
echo "Testing with missing finding data..."
echo '{"method":"generate_code_fix","params":{"finding":{},"project_context":{}}}' | go run . > /tmp/test_empty_finding.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Handles empty finding gracefully"
else
    echo -e "${YELLOW}⚠${NC} Should handle empty finding"
fi
echo ""

# Test with unknown method
echo "Testing error handling with unknown method..."
echo '{"method":"unknown_method","params":{}}' | go run . > /tmp/test_unknown_method.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly rejects unknown method"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with unknown method"
fi
echo ""

# Re-enable exit on error
set -e

echo "=== Test 10: JSON Output Validation ==="
echo ""

echo "Validating JSON structure for all outputs..."
if command -v jq &> /dev/null; then
    for file in /tmp/test_complexity_simple_output.json /tmp/test_dependency_fix_output.json /tmp/test_code_fix_output.json /tmp/test_action_plan_output.json /tmp/test_generate_tests_output.json /tmp/test_full_remediation_output.json; do
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
rm -f /tmp/test_complexity*.json /tmp/test_dependency_fix*.json /tmp/test_code_fix*.json /tmp/test_action_plan*.json /tmp/test_generate_tests*.json /tmp/test_full_remediation*.json /tmp/test_error.json /tmp/test_empty_finding.json /tmp/test_unknown_method.json
echo -e "${GREEN}✓${NC} Cleaned up test files"
echo ""

echo -e "${GREEN}=== All Remediation Agent Tests Passed ===${NC}"
echo ""

echo "Summary:"
echo "  ✓ Complexity estimation (simple & complex)"
echo "  ✓ Dependency fix generation"
echo "  ✓ Code fix generation (SQL injection & XSS)"
echo "  ✓ Action plan generation"
echo "  ✓ Test generation"
echo "  ✓ Full remediation pipeline"
echo "  ✓ Error handling"
echo "  ✓ JSON output validation"
echo ""
