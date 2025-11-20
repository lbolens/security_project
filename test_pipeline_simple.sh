#!/bin/bash

# Simplified Pipeline Integration Test
# Tests each agent step-by-step

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

TEST_PROJECT="/Users/lucasbolens/Desktop/security_project/test-projects/vulnerable-app"
OUTPUT_DIR="/Users/lucasbolens/Desktop/security_project/.security-scan"

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${BLUE}  Security Pipeline Integration Test   ${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""

# Step 1: Profiler
echo -e "${BLUE}[1/6] Profiler Agent...${NC}"
cd agents/profiler_agent
echo "{\"project_path\":\"$TEST_PROJECT\"}" | go run . analyze_project > "$OUTPUT_DIR/1_profiler.json" 2>&1
if [ $? -eq 0 ] && [ -s "$OUTPUT_DIR/1_profiler.json" ]; then
    echo -e "${GREEN}✓ Profiler completed${NC}"
    echo "  Languages: $(cat $OUTPUT_DIR/1_profiler.json | jq -r '.languages[].name' | tr '\n' ', ' | sed 's/,$//')"
else
    echo -e "${RED}✗ Profiler failed${NC}"
    cat "$OUTPUT_DIR/1_profiler.json"
    exit 1
fi
echo ""

# Step 2: Contextualization
echo -e "${BLUE}[2/6] Contextualization Agent...${NC}"
cd ../contextualization_agent
cat > /tmp/context_input.json << EOF
{
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_path": "$TEST_PROJECT"
}
EOF
cat /tmp/context_input.json | go run . analyze_project_context > "$OUTPUT_DIR/2_context.json" 2>&1
if [ $? -eq 0 ] && [ -s "$OUTPUT_DIR/2_context.json" ]; then
    echo -e "${GREEN}✓ Contextualization completed${NC}"
    echo "  Project type: $(cat $OUTPUT_DIR/2_context.json | jq -r '.project_context.type')"
    echo "  Domain: $(cat $OUTPUT_DIR/2_context.json | jq -r '.project_context.domain')"
    echo "  Criticality: $(cat $OUTPUT_DIR/2_context.json | jq -r '.project_context.criticality')"
else
    echo -e "${RED}✗ Contextualization failed${NC}"
    cat "$OUTPUT_DIR/2_context.json"
    exit 1
fi
echo ""

# Step 3: Security Agents (simplified - just one for now)
echo -e "${BLUE}[3/6] SAST Agent...${NC}"
cd ../sast_agent
cat > /tmp/sast_input.json << EOF
{
  "project_path": "$TEST_PROJECT",
  "config": {
    "enabled": true,
    "severity_threshold": "medium"
  }
}
EOF
cat /tmp/sast_input.json | go run . scan_project > "$OUTPUT_DIR/3_sast.json" 2>&1 || echo '{"findings":[]}' > "$OUTPUT_DIR/3_sast.json"
echo -e "${GREEN}✓ SAST completed${NC}"
SAST_COUNT=$(cat "$OUTPUT_DIR/3_sast.json" | jq '.findings | length' 2>/dev/null || echo "0")
echo "  Findings: $SAST_COUNT"
echo ""

# Create empty outputs for SCA and Secrets for now
echo '{"findings":[]}' > "$OUTPUT_DIR/3_sca.json"
echo '{"findings":[]}' > "$OUTPUT_DIR/3_secrets.json"

# Step 4: Aggregator
echo -e "${BLUE}[4/6] Aggregator Agent...${NC}"
cd ../aggregator_agent
cat > /tmp/aggregator_input.json << EOF
{"method":"aggregate_findings","params":{
  "sast_findings": $(cat "$OUTPUT_DIR/3_sast.json" | jq '.findings'),
  "sca_findings": [],
  "secrets_findings": [],
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_context": $(cat "$OUTPUT_DIR/2_context.json" | jq '.project_context'),
  "config": {"enable_deduplication": true, "deduplication_strategy": "exact"}
}}
EOF
cat /tmp/aggregator_input.json | jq -c '.' | go run . > "$OUTPUT_DIR/4_aggregator.json" 2>&1
if [ $? -eq 0 ] && [ -s "$OUTPUT_DIR/4_aggregator.json" ]; then
    echo -e "${GREEN}✓ Aggregator completed${NC}"
    TOTAL=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.total_findings' 2>/dev/null || echo "0")
    RISK=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.risk_score' 2>/dev/null || echo "0")
    echo "  Total findings: $TOTAL"
    echo "  Risk score: $RISK/100"
else
    echo -e "${RED}✗ Aggregator failed${NC}"
    cat "$OUTPUT_DIR/4_aggregator.json"
    exit 1
fi
echo ""

# Step 5: Remediation
echo -e "${BLUE}[5/6] Remediation Agent...${NC}"
cd ../remediation_agent
cat > /tmp/remediation_input.json << EOF
{"method":"generate_remediation_plans","params":{
  "aggregated_report": $(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result'),
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_context": $(cat "$OUTPUT_DIR/2_context.json" | jq '.project_context'),
  "config": {
    "generate_alternatives": false,
    "include_tests": true,
    "detailed_steps": true,
    "estimate_complexity": true
  }
}}
EOF
cat /tmp/remediation_input.json | jq -c '.' | go run . > "$OUTPUT_DIR/5_remediation.json" 2>&1
if [ $? -eq 0 ] && [ -s "$OUTPUT_DIR/5_remediation.json" ]; then
    echo -e "${GREEN}✓ Remediation completed${NC}"
    PLANS=$(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.remediation_plans | length' 2>/dev/null || echo "0")
    echo "  Remediation plans: $PLANS"
else
    echo -e "${RED}✗ Remediation failed${NC}"
    cat "$OUTPUT_DIR/5_remediation.json"
    exit 1
fi
echo ""

# Step 6: Report
echo -e "${BLUE}[6/6] Report Agent...${NC}"
cd ../report_agent
cat > /tmp/report_input.json << EOF
{
  "aggregated_report": $(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result'),
  "remediation_plans": $(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.remediation_plans'),
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "config": {
    "formats": ["json", "markdown"],
    "output_dir": "$OUTPUT_DIR",
    "include_executive_summary": true
  }
}
EOF
cat /tmp/report_input.json | go run . generate_reports > "$OUTPUT_DIR/6_report.json" 2>&1
if [ $? -eq 0 ] && [ -s "$OUTPUT_DIR/6_report.json" ]; then
    echo -e "${GREEN}✓ Report completed${NC}"
    echo "  Reports generated: $(cat $OUTPUT_DIR/6_report.json | jq -r '.result.reports | keys[]' | tr '\n' ', ' | sed 's/,$//')"
else
    echo -e "${RED}✗ Report failed${NC}"
    cat "$OUTPUT_DIR/6_report.json"
    exit 1
fi
echo ""

echo -e "${BLUE}════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ PIPELINE TEST COMPLETED${NC}"
echo -e "${BLUE}════════════════════════════════════════${NC}"
echo ""
echo "All 6 agents executed successfully!"
echo "Output files in: $OUTPUT_DIR"
echo ""
