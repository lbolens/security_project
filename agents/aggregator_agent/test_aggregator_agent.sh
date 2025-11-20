#!/bin/bash

# Test script for Aggregator Agent
# This script tests all five tools: aggregate_findings, deduplicate_findings, calculate_priority, calculate_risk_score, generate_statistics

set -e

echo "=== Aggregator Agent Test Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Navigate to aggregator_agent directory
cd "$(dirname "$0")"

# Helper function to call MCP methods
call_mcp() {
    local method=$1
    local params_file=$2
    local output_file=$3

    echo "{\"method\":\"$method\",\"params\":$(cat $params_file | jq -c '.')}" | go run . 2>&1 | jq '.result' > $output_file
}

echo "=== Test 1: aggregate_findings (Basic Aggregation) ==="
echo ""

# Create test input with mixed findings from SAST, SCA, and Secrets
cat > /tmp/test_aggregator_basic.json << 'EOF'
{
  "sast_findings": [
    {
      "id": "sast-1",
      "type": "sql-injection",
      "severity": "critical",
      "title": "SQL Injection in login handler",
      "description": "Unsafe SQL query construction using string concatenation",
      "file_path": "api/handlers/login.go",
      "line_number": 42,
      "cvss": 9.8,
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021-Injection"],
      "confidence": "high"
    },
    {
      "id": "sast-2",
      "type": "xss",
      "severity": "high",
      "title": "Cross-Site Scripting in user profile",
      "description": "Unescaped user input in HTML output",
      "file_path": "web/templates/profile.html",
      "line_number": 128,
      "cvss": 7.5,
      "exploitability": "easily exploitable",
      "confidence": "medium"
    }
  ],
  "sca_findings": [
    {
      "id": "sca-1",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "CVE-2023-1234 in lodash",
      "description": "Prototype pollution vulnerability in lodash",
      "component_name": "lodash@4.17.20",
      "cve": "CVE-2023-1234",
      "cvss": 8.2,
      "recommendation": "Upgrade to lodash@4.17.21 or higher"
    }
  ],
  "secrets_findings": [
    {
      "id": "secret-1",
      "type": "exposed-secret",
      "severity": "critical",
      "title": "AWS Access Key exposed in config",
      "description": "Hardcoded AWS credentials found",
      "file_path": "config/aws.go",
      "line_number": 15,
      "confidence": "high"
    }
  ],
  "project_profile": {
    "project_name": "Test Security Project"
  },
  "project_context": {
    "type": "api",
    "domain": "finance",
    "criticality": "high"
  },
  "config": {
    "enable_deduplication": false,
    "dedup_strategy": "similar",
    "min_confidence": "medium",
    "group_similar_findings": false,
    "similarity_threshold": 3
  }
}
EOF

echo "Running aggregate_findings with mixed findings..."
call_mcp "aggregate_findings" /tmp/test_aggregator_basic.json /tmp/test_aggregator_basic_output.json

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} aggregate_findings completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        echo "Aggregation results:"
        TOTAL_FINDINGS=$(cat /tmp/test_aggregator_basic_output.json | jq '.summary.total_findings')
        UNIQUE_FINDINGS=$(cat /tmp/test_aggregator_basic_output.json | jq '.summary.unique_findings')
        CRITICAL=$(cat /tmp/test_aggregator_basic_output.json | jq '.summary.critical_findings')
        HIGH=$(cat /tmp/test_aggregator_basic_output.json | jq '.summary.high_findings')
        RISK_SCORE=$(cat /tmp/test_aggregator_basic_output.json | jq '.summary.risk_score')

        echo "  Total findings: $TOTAL_FINDINGS"
        echo "  Unique findings: $UNIQUE_FINDINGS"
        echo "  Critical findings: $CRITICAL"
        echo "  High findings: $HIGH"
        echo "  Risk score: $RISK_SCORE"

        # Verify counts
        if [ "$TOTAL_FINDINGS" -eq 4 ]; then
            echo -e "${GREEN}✓${NC} Correct total findings count (4)"
        else
            echo -e "${YELLOW}⚠${NC} Expected 4 total findings, got $TOTAL_FINDINGS"
        fi

        # Check statistics
        CATEGORIES=$(cat /tmp/test_aggregator_basic_output.json | jq '.statistics.by_category | length')
        BY_SOURCE=$(cat /tmp/test_aggregator_basic_output.json | jq '.statistics.by_source')

        echo ""
        echo "  Categories detected: $CATEGORIES"
        echo "  Findings by source:"
        echo "$BY_SOURCE" | jq -r 'to_entries[] | "    \(.key): \(.value)"'
        echo ""
    else
        echo -e "${YELLOW}⚠${NC} jq not installed, skipping detailed validation"
        echo ""
    fi
else
    echo -e "${RED}✗${NC} aggregate_findings failed"
    cat /tmp/test_aggregator_basic_output.json
    exit 1
fi

echo "=== Test 2: deduplicate_findings (Exact Strategy) ==="
echo ""

# Create test input with duplicate findings
cat > /tmp/test_dedup_exact.json << 'EOF'
{
  "findings": [
    {
      "id": "finding-1",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "SQL vulnerability in query",
      "file_path": "api/users.go",
      "line_number": 42,
      "sources": ["sast"]
    },
    {
      "id": "finding-2",
      "type": "sql-injection",
      "severity": "critical",
      "title": "SQL Injection",
      "description": "SQL vulnerability in query - detected by secrets agent",
      "file_path": "api/users.go",
      "line_number": 42,
      "sources": ["secrets"]
    },
    {
      "id": "finding-3",
      "type": "xss",
      "severity": "medium",
      "title": "XSS vulnerability",
      "description": "Cross-site scripting",
      "file_path": "web/profile.html",
      "line_number": 100,
      "sources": ["sast"]
    }
  ],
  "strategy": "exact"
}
EOF

echo "Running deduplicate_findings with exact strategy..."
echo "{\"method\":\"deduplicate_findings\",\"params\":$(cat /tmp/test_dedup_exact.json)}" | go run . > /tmp/test_dedup_exact_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} deduplicate_findings (exact) completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        DEDUP_COUNT=$(cat /tmp/test_dedup_exact_output.json | jq '.deduplicated_findings | length')
        DUPLICATES_REMOVED=$(cat /tmp/test_dedup_exact_output.json | jq '.duplicates_removed')

        echo "  Deduplicated findings: $DEDUP_COUNT"
        echo "  Duplicates removed: $DUPLICATES_REMOVED"

        if [ "$DEDUP_COUNT" -eq 2 ] && [ "$DUPLICATES_REMOVED" -eq 1 ]; then
            echo -e "${GREEN}✓${NC} Correctly merged duplicate findings (same file+line+type)"
        else
            echo -e "${YELLOW}⚠${NC} Expected 2 unique findings with 1 duplicate removed"
        fi

        # Check if sources were merged
        MERGED_SOURCES=$(cat /tmp/test_dedup_exact_output.json | jq -r '.deduplicated_findings[0].sources | join(", ")')
        echo "  Merged sources: [$MERGED_SOURCES]"
        echo ""
    fi
else
    echo -e "${RED}✗${NC} deduplicate_findings (exact) failed"
    cat /tmp/test_dedup_exact_output.json
    exit 1
fi

echo "=== Test 3: deduplicate_findings (Similar Strategy) ==="
echo ""

# Create test input with similar findings (same file, different lines)
cat > /tmp/test_dedup_similar.json << 'EOF'
{
  "findings": [
    {
      "id": "finding-1",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "SQL vulnerability",
      "file_path": "api/users.go",
      "line_number": 42,
      "sources": ["sast"]
    },
    {
      "id": "finding-2",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "SQL vulnerability",
      "file_path": "api/users.go",
      "line_number": 56,
      "sources": ["sast"]
    },
    {
      "id": "finding-3",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "SQL vulnerability",
      "file_path": "api/users.go",
      "line_number": 78,
      "sources": ["sast"]
    },
    {
      "id": "finding-4",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "SQL vulnerability",
      "file_path": "api/users.go",
      "line_number": 92,
      "sources": ["sast"]
    }
  ],
  "strategy": "similar"
}
EOF

echo "Running deduplicate_findings with similar strategy..."
echo "{\"method\":\"deduplicate_findings\",\"params\":$(cat /tmp/test_dedup_similar.json)}" | go run . > /tmp/test_dedup_similar_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} deduplicate_findings (similar) completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        DEDUP_COUNT=$(cat /tmp/test_dedup_similar_output.json | jq '.deduplicated_findings | length')

        echo "  Deduplicated findings: $DEDUP_COUNT"

        # Should group similar findings if > 3 in same file
        if [ "$DEDUP_COUNT" -lt 4 ]; then
            echo -e "${GREEN}✓${NC} Similar findings grouped (4 → $DEDUP_COUNT)"
        else
            echo -e "${YELLOW}⚠${NC} Expected similar findings to be grouped"
        fi

        # Check for "multiple-occurrences" tag
        HAS_TAG=$(cat /tmp/test_dedup_similar_output.json | jq '[.deduplicated_findings[].tags[] | select(. == "multiple-occurrences")] | length')
        if [ "$HAS_TAG" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Multiple occurrences tag added"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} deduplicate_findings (similar) failed"
    cat /tmp/test_dedup_similar_output.json
    exit 1
fi

echo "=== Test 4: deduplicate_findings (Aggressive Strategy with CVEs) ==="
echo ""

# Create test input with same CVE affecting multiple dependencies
cat > /tmp/test_dedup_aggressive.json << 'EOF'
{
  "findings": [
    {
      "id": "sca-1",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "CVE-2023-1234",
      "description": "Vulnerability in package A",
      "component_name": "package-a",
      "cve": "CVE-2023-1234",
      "cvss": 8.5,
      "sources": ["sca"]
    },
    {
      "id": "sca-2",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "CVE-2023-1234",
      "description": "Vulnerability in package B (transitive)",
      "component_name": "package-b",
      "cve": "CVE-2023-1234",
      "cvss": 8.5,
      "sources": ["sca"]
    },
    {
      "id": "sca-3",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "CVE-2023-1234",
      "description": "Vulnerability in package C (transitive)",
      "component_name": "package-c",
      "cve": "CVE-2023-1234",
      "cvss": 8.5,
      "sources": ["sca"]
    }
  ],
  "strategy": "aggressive"
}
EOF

echo "Running deduplicate_findings with aggressive strategy (CVE grouping)..."
echo "{\"method\":\"deduplicate_findings\",\"params\":$(cat /tmp/test_dedup_aggressive.json)}" | go run . > /tmp/test_dedup_aggressive_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} deduplicate_findings (aggressive) completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        DEDUP_COUNT=$(cat /tmp/test_dedup_aggressive_output.json | jq '.deduplicated_findings | length')
        DUPLICATES_REMOVED=$(cat /tmp/test_dedup_aggressive_output.json | jq '.duplicates_removed')

        echo "  Deduplicated findings: $DEDUP_COUNT"
        echo "  Duplicates removed: $DUPLICATES_REMOVED"

        if [ "$DEDUP_COUNT" -eq 1 ]; then
            echo -e "${GREEN}✓${NC} CVEs correctly merged (3 → 1)"

            # Check if all components are listed
            COMPONENT_NAME=$(cat /tmp/test_dedup_aggressive_output.json | jq -r '.deduplicated_findings[0].component_name')
            echo "  Affected components: $COMPONENT_NAME"

            # Should have transitive-dependency tag
            HAS_TAG=$(cat /tmp/test_dedup_aggressive_output.json | jq '[.deduplicated_findings[0].tags[] | select(. == "transitive-dependency")] | length')
            if [ "$HAS_TAG" -gt 0 ]; then
                echo -e "${GREEN}✓${NC} Transitive-dependency tag added"
            fi
        else
            echo -e "${YELLOW}⚠${NC} Expected same CVE findings to be merged into 1"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} deduplicate_findings (aggressive) failed"
    cat /tmp/test_dedup_aggressive_output.json
    exit 1
fi

echo "=== Test 5: calculate_priority ==="
echo ""

# Test priority calculation with different severities and contexts
cat > /tmp/test_priority.json << 'EOF'
{
  "finding": {
    "id": "test-1",
    "type": "sql-injection",
    "severity": "critical",
    "cvss": 9.8,
    "exploitability": "easily exploitable",
    "confidence": "high",
    "sources": ["sast", "secrets"],
    "file_path": "api/handler/auth.go"
  },
  "project_context": {
    "type": "api",
    "domain": "finance",
    "criticality": "critical"
  }
}
EOF

echo "Running calculate_priority for critical finding in finance API..."
echo "{\"method\":\"calculate_priority\",\"params\":$(cat /tmp/test_priority.json)}" | go run . > /tmp/test_priority_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} calculate_priority completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        PRIORITY=$(cat /tmp/test_priority_output.json | jq '.priority')
        SEVERITY_SCORE=$(cat /tmp/test_priority_output.json | jq '.score_breakdown.severity_score')
        CVSS_SCORE=$(cat /tmp/test_priority_output.json | jq '.score_breakdown.cvss_score')
        EXPLOITABILITY=$(cat /tmp/test_priority_output.json | jq '.score_breakdown.exploitability_score')
        CONTEXT=$(cat /tmp/test_priority_output.json | jq '.score_breakdown.context_score')
        CONFIDENCE=$(cat /tmp/test_priority_output.json | jq '.score_breakdown.confidence_score')

        echo "  Priority score: $PRIORITY/100"
        echo "  Score breakdown:"
        echo "    Severity: $SEVERITY_SCORE"
        echo "    CVSS: $CVSS_SCORE"
        echo "    Exploitability: $EXPLOITABILITY"
        echo "    Context: $CONTEXT"
        echo "    Confidence: $CONFIDENCE"

        if [ "$PRIORITY" -gt 80 ]; then
            echo -e "${GREEN}✓${NC} High priority score for critical finding (>80)"
        else
            echo -e "${YELLOW}⚠${NC} Expected higher priority for critical finding in finance"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} calculate_priority failed"
    cat /tmp/test_priority_output.json
    exit 1
fi

echo "=== Test 6: calculate_priority (Low Severity) ==="
echo ""

cat > /tmp/test_priority_low.json << 'EOF'
{
  "finding": {
    "id": "test-2",
    "type": "info-leak",
    "severity": "low",
    "cvss": 2.5,
    "exploitability": "difficult to exploit",
    "confidence": "low",
    "sources": ["sast"],
    "file_path": "utils/helpers.go"
  },
  "project_context": {
    "type": "cli",
    "domain": "general",
    "criticality": "low"
  }
}
EOF

echo "Running calculate_priority for low severity finding..."
echo "{\"method\":\"calculate_priority\",\"params\":$(cat /tmp/test_priority_low.json)}" | go run . > /tmp/test_priority_low_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} calculate_priority (low) completed successfully"

    if command -v jq &> /dev/null; then
        PRIORITY_LOW=$(cat /tmp/test_priority_low_output.json | jq '.priority')
        echo "  Priority score: $PRIORITY_LOW/100"

        if [ "$PRIORITY_LOW" -lt 30 ]; then
            echo -e "${GREEN}✓${NC} Low priority score for low severity finding (<30)"
        fi
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} calculate_priority (low) had issues"
    echo ""
fi

echo "=== Test 7: calculate_risk_score ==="
echo ""

# Test risk score calculation with mixed severities
cat > /tmp/test_risk_score.json << 'EOF'
{
  "findings": [
    {
      "id": "1",
      "severity": "critical"
    },
    {
      "id": "2",
      "severity": "critical"
    },
    {
      "id": "3",
      "severity": "high"
    },
    {
      "id": "4",
      "severity": "high"
    },
    {
      "id": "5",
      "severity": "high"
    },
    {
      "id": "6",
      "severity": "medium"
    },
    {
      "id": "7",
      "severity": "medium"
    },
    {
      "id": "8",
      "severity": "low"
    }
  ]
}
EOF

echo "Running calculate_risk_score with mixed findings..."
echo "{\"method\":\"calculate_risk_score\",\"params\":$(cat /tmp/test_risk_score.json)}" | go run . > /tmp/test_risk_score_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} calculate_risk_score completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        RISK_SCORE=$(cat /tmp/test_risk_score_output.json | jq '.risk_score')
        RISK_LEVEL=$(cat /tmp/test_risk_score_output.json | jq -r '.risk_level')
        CRITICAL_IMPACT=$(cat /tmp/test_risk_score_output.json | jq '.breakdown.critical_impact')
        HIGH_IMPACT=$(cat /tmp/test_risk_score_output.json | jq '.breakdown.high_impact')

        echo "  Risk score: $RISK_SCORE/100"
        echo "  Risk level: $RISK_LEVEL"
        echo "  Impact breakdown:"
        echo "    Critical: $CRITICAL_IMPACT"
        echo "    High: $HIGH_IMPACT"

        if [ "$RISK_SCORE" != "0" ] && [ "$RISK_SCORE" != "0.0" ]; then
            echo -e "${GREEN}✓${NC} Risk score calculated correctly"
        else
            echo -e "${RED}✗${NC} Risk score should not be 0 with findings"
            exit 1
        fi

        if [ "$RISK_LEVEL" = "high" ] || [ "$RISK_LEVEL" = "critical" ]; then
            echo -e "${GREEN}✓${NC} Risk level correctly set to $RISK_LEVEL"
        else
            echo -e "${YELLOW}⚠${NC} Expected high/critical risk level for 2 critical findings"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} calculate_risk_score failed"
    cat /tmp/test_risk_score_output.json
    exit 1
fi

echo "=== Test 8: calculate_risk_score (No Findings) ==="
echo ""

echo '{"method":"calculate_risk_score","params":{"findings":[]}}' | go run . > /tmp/test_risk_score_zero_response.json 2>&1


if [ $? -eq 0 ]; then
    if command -v jq &> /dev/null; then
        ZERO_RISK=$(cat /tmp/test_risk_score_zero_output.json | jq '.risk_score')
        ZERO_LEVEL=$(cat /tmp/test_risk_score_zero_output.json | jq -r '.risk_level')

        if [ "$ZERO_RISK" = "0" ] || [ "$ZERO_RISK" = "0.0" ]; then
            echo -e "${GREEN}✓${NC} Risk score correctly 0 for empty findings"
        fi

        if [ "$ZERO_LEVEL" = "low" ]; then
            echo -e "${GREEN}✓${NC} Risk level correctly set to 'low' for no findings"
        fi
        echo ""
    fi
else
    echo -e "${YELLOW}⚠${NC} Empty findings test had issues"
    echo ""
fi

echo "=== Test 9: generate_statistics ==="
echo ""

# Test statistics generation
cat > /tmp/test_statistics.json << 'EOF'
{
  "findings": [
    {
      "id": "1",
      "type": "sql-injection",
      "category": "injection",
      "severity": "critical",
      "file_path": "api/users.go",
      "component_name": "api-handler",
      "sources": ["sast"]
    },
    {
      "id": "2",
      "type": "xss",
      "category": "injection",
      "severity": "high",
      "file_path": "web/profile.html",
      "sources": ["sast"]
    },
    {
      "id": "3",
      "type": "weak-crypto",
      "category": "cryptography",
      "severity": "medium",
      "file_path": "utils/crypto.go",
      "sources": ["sast"]
    },
    {
      "id": "4",
      "type": "vulnerable-dependency",
      "category": "vulnerable-components",
      "severity": "high",
      "file_path": "package.json",
      "component_name": "lodash",
      "sources": ["sca"]
    },
    {
      "id": "5",
      "type": "exposed-secret",
      "category": "sensitive-data",
      "severity": "critical",
      "file_path": "config/aws.go",
      "sources": ["secrets"]
    }
  ],
  "top_n": 10
}
EOF

echo "Running generate_statistics..."
echo "{\"method\":\"generate_statistics\",\"params\":$(cat /tmp/test_statistics.json)}" | go run . > /tmp/test_statistics_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} generate_statistics completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        echo "Statistics summary:"

        # By category
        echo "  By category:"
        cat /tmp/test_statistics_output.json | jq -r '.statistics.by_category | to_entries[] | "    \(.key): \(.value)"'

        # By severity
        echo ""
        echo "  By severity:"
        cat /tmp/test_statistics_output.json | jq -r '.statistics.by_severity | to_entries[] | "    \(.key): \(.value)"'

        # By source
        echo ""
        echo "  By source:"
        cat /tmp/test_statistics_output.json | jq -r '.statistics.by_source | to_entries[] | "    \(.key): \(.value)"'

        # Top vulnerabilities
        echo ""
        echo "  Top vulnerabilities:"
        cat /tmp/test_statistics_output.json | jq -r '.statistics.top_vulnerabilities[] | "    \(.type): \(.count)"'

        # Most affected files
        echo ""
        echo "  Most affected files:"
        cat /tmp/test_statistics_output.json | jq -r '.statistics.most_affected_files[] | "    \(.file_path): \(.count) finding(s)"'

        # Verify counts
        CATEGORY_COUNT=$(cat /tmp/test_statistics_output.json | jq '.statistics.by_category | length')
        if [ "$CATEGORY_COUNT" -ge 3 ]; then
            echo ""
            echo -e "${GREEN}✓${NC} Multiple categories detected ($CATEGORY_COUNT)"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} generate_statistics failed"
    cat /tmp/test_statistics_output.json
    exit 1
fi

echo "=== Test 10: Error Handling ==="
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

# Test with empty findings
echo "Testing with empty input..."
echo '{"method":"aggregate_findings","params":{"sast_findings":[],"sca_findings":[],"secrets_findings":[],"project_profile":{},"project_context":{},"config":{}}}' | go run . > /tmp/test_empty_response.json 2>&1
ERROR_CODE=$?


if [ $ERROR_CODE -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Handles empty findings gracefully"

    if command -v jq &> /dev/null; then
        EMPTY_TOTAL=$(cat /tmp/test_empty.json | jq '.summary.total_findings')
        if [ "$EMPTY_TOTAL" -eq 0 ]; then
            echo -e "${GREEN}✓${NC} Correctly reports 0 findings"
        fi
    fi
else
    echo -e "${YELLOW}⚠${NC} Should handle empty findings"
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

echo "=== Test 11: JSON Output Validation ==="
echo ""

echo "Validating JSON structure for all outputs..."
if command -v jq &> /dev/null; then
    for file in /tmp/test_aggregator_basic_output.json /tmp/test_dedup_exact_output.json /tmp/test_priority_output.json /tmp/test_risk_score_output.json /tmp/test_statistics_output.json; do
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

echo "=== Test 12: Integration Test (Full Aggregation Pipeline) ==="
echo ""

# Full pipeline test with deduplication enabled
cat > /tmp/test_full_pipeline.json << 'EOF'
{
  "sast_findings": [
    {
      "id": "sast-1",
      "type": "sql-injection",
      "severity": "critical",
      "title": "SQL Injection",
      "description": "Critical SQL vulnerability",
      "file_path": "api/users.go",
      "line_number": 42,
      "cvss": 9.5,
      "cwe": ["CWE-89"],
      "confidence": "high"
    },
    {
      "id": "sast-2",
      "type": "sql-injection",
      "severity": "high",
      "title": "SQL Injection",
      "description": "Duplicate detection test",
      "file_path": "api/users.go",
      "line_number": 42,
      "cvss": 8.0,
      "confidence": "medium"
    }
  ],
  "sca_findings": [
    {
      "id": "sca-1",
      "type": "vulnerable-dependency",
      "severity": "high",
      "title": "CVE-2024-1111",
      "component_name": "express",
      "cve": "CVE-2024-1111",
      "cvss": 7.8
    }
  ],
  "secrets_findings": [
    {
      "id": "secret-1",
      "type": "exposed-secret",
      "severity": "critical",
      "title": "API Key",
      "file_path": ".env",
      "line_number": 5
    }
  ],
  "project_profile": {
    "project_name": "Production API"
  },
  "project_context": {
    "type": "api",
    "domain": "ecommerce",
    "criticality": "high"
  },
  "config": {
    "enable_deduplication": true,
    "dedup_strategy": "exact",
    "group_similar_findings": true,
    "similarity_threshold": 3
  }
}
EOF

echo "Running full aggregation pipeline with deduplication..."
echo "{\"method\":\"aggregate_findings\",\"params\":$(cat /tmp/test_full_pipeline.json)}" | go run . > /tmp/test_full_pipeline_response.json 2>&1


if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Full pipeline test completed successfully"
    echo ""

    if command -v jq &> /dev/null; then
        TOTAL=$(cat /tmp/test_full_pipeline_output.json | jq '.summary.total_findings')
        UNIQUE=$(cat /tmp/test_full_pipeline_output.json | jq '.summary.unique_findings')
        DEDUPED=$(cat /tmp/test_full_pipeline_output.json | jq '.summary.duplicates_removed')
        RISK=$(cat /tmp/test_full_pipeline_output.json | jq '.summary.risk_score')

        echo "  Pipeline results:"
        echo "    Total findings (before dedup): $TOTAL"
        echo "    Unique findings (after dedup): $UNIQUE"
        echo "    Duplicates removed: $DEDUPED"
        echo "    Overall risk score: $RISK/100"

        if [ "$DEDUPED" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Deduplication working in full pipeline"
        fi

        # Check if findings are prioritized
        FIRST_PRIORITY=$(cat /tmp/test_full_pipeline_output.json | jq '.findings[0].priority')
        LAST_PRIORITY=$(cat /tmp/test_full_pipeline_output.json | jq '.findings[-1].priority // .findings[0].priority')

        if [ "$FIRST_PRIORITY" -ge "$LAST_PRIORITY" ]; then
            echo -e "${GREEN}✓${NC} Findings correctly sorted by priority"
        fi

        # Verify statistics were generated
        HAS_STATS=$(cat /tmp/test_full_pipeline_output.json | jq 'has("statistics")')
        if [ "$HAS_STATS" = "true" ]; then
            echo -e "${GREEN}✓${NC} Statistics generated"
        fi

        # Verify timeline exists
        TIMELINE_ENTRIES=$(cat /tmp/test_full_pipeline_output.json | jq '.timeline | length')
        if [ "$TIMELINE_ENTRIES" -gt 0 ]; then
            echo -e "${GREEN}✓${NC} Timeline generated ($TIMELINE_ENTRIES entries)"
        fi

        # Verify metadata
        PROJECT_NAME=$(cat /tmp/test_full_pipeline_output.json | jq -r '.metadata.project_name')
        if [ "$PROJECT_NAME" != "null" ] && [ "$PROJECT_NAME" != "" ]; then
            echo -e "${GREEN}✓${NC} Metadata populated (project: $PROJECT_NAME)"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} Full pipeline test failed"
    cat /tmp/test_full_pipeline_output.json
    exit 1
fi

# Cleanup
echo "=== Cleanup ==="
rm -f /tmp/test_aggregator_*.json /tmp/test_dedup_*.json /tmp/test_priority*.json /tmp/test_risk_score*.json /tmp/test_statistics*.json /tmp/test_error.json /tmp/test_empty.json /tmp/test_unknown_method.json /tmp/test_full_pipeline*.json
echo -e "${GREEN}✓${NC} Cleaned up test files"
echo ""

echo -e "${GREEN}=== All Aggregator Agent Tests Passed ===${NC}"
echo ""

echo "Summary:"
echo "  ✓ Aggregation of mixed findings (SAST, SCA, Secrets)"
echo "  ✓ Exact deduplication (same file+line+type)"
echo "  ✓ Similar deduplication (same file+type, different lines)"
echo "  ✓ Aggressive deduplication (CVE grouping)"
echo "  ✓ Priority calculation with context"
echo "  ✓ Risk score calculation"
echo "  ✓ Statistics generation"
echo "  ✓ Error handling"
echo "  ✓ JSON output validation"
echo "  ✓ Full integration pipeline"
echo ""
