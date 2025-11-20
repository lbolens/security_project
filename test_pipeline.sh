#!/bin/bash

# Full Pipeline Integration Test
# Tests the complete security analysis pipeline from profiling to reporting

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_PROJECT="/Users/lucasbolens/Desktop/security_project/test-projects/vulnerable-app"
OUTPUT_DIR="/Users/lucasbolens/Desktop/security_project/.security-scan"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Security Pipeline - Full Integration Test                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Helper function to call agents via CLI
call_agent() {
    local agent_dir=$1
    local tool_name=$2
    local params_file=$3
    local output_file=$4

    cat "$params_file" | (cd "$agent_dir" && go run . "$tool_name") 2>&1 > "$output_file"
}

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 1: Profiler Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "Analyzing project structure..."

cat > "$OUTPUT_DIR/profiler_input.json" << EOF
{
  "project_path": "$TEST_PROJECT"
}
EOF

call_agent \
    "agents/profiler_agent" \
    "analyze_project" \
    "$OUTPUT_DIR/profiler_input.json" \
    "$OUTPUT_DIR/profiler_output.json"

if [ -s "$OUTPUT_DIR/profiler_output.json" ] && [ "$(cat $OUTPUT_DIR/profiler_output.json)" != "null" ]; then
    echo -e "${GREEN}✓${NC} Profiler agent completed successfully"
    echo ""
    echo "Project Profile:"
    cat "$OUTPUT_DIR/profiler_output.json" | jq '{
        languages: .languages[0:3],
        frameworks: .frameworks[0:3],
        total_files: .statistics.total_files,
        total_lines: .statistics.total_lines
    }'
    echo ""
else
    echo -e "${RED}✗${NC} Profiler agent failed"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 2: Contextualization Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "Determining project context and which agents to activate..."

# Create contextualization input with profiler output
cat > "$OUTPUT_DIR/context_input.json" << EOF
{
  "project_profile": $(cat "$OUTPUT_DIR/profiler_output.json"),
  "project_path": "$TEST_PROJECT"
}
EOF

call_agent \
    "agents/contextualization_agent" \
    "analyze_context" \
    "$OUTPUT_DIR/context_input.json" \
    "$OUTPUT_DIR/context_output.json"

if [ -s "$OUTPUT_DIR/context_output.json" ] && [ "$(cat $OUTPUT_DIR/context_output.json)" != "null" ]; then
    echo -e "${GREEN}✓${NC} Contextualization agent completed successfully"
    echo ""
    echo "Project Context:"
    cat "$OUTPUT_DIR/context_output.json" | jq '{
        type: .project_context.type,
        domain: .project_context.domain,
        criticality: .project_context.criticality,
        agents: .agent_config
    }'
    echo ""

    # Extract which agents to run
    ENABLE_SAST=$(cat "$OUTPUT_DIR/context_output.json" | jq -r '.agent_config.sast.enabled')
    ENABLE_SCA=$(cat "$OUTPUT_DIR/context_output.json" | jq -r '.agent_config.sca.enabled')
    ENABLE_SECRETS=$(cat "$OUTPUT_DIR/context_output.json" | jq -r '.agent_config.secrets.enabled')

    echo "Agents to activate:"
    echo "  - SAST: $ENABLE_SAST"
    echo "  - SCA: $ENABLE_SCA"
    echo "  - Secrets: $ENABLE_SECRETS"
    echo ""
else
    echo -e "${RED}✗${NC} Contextualization agent failed"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 3: Security Scanning Agents (Parallel)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Create empty findings arrays
echo '{"findings":[]}' > "$OUTPUT_DIR/sast_output.json"
echo '{"findings":[]}' > "$OUTPUT_DIR/sca_output.json"
echo '{"findings":[]}' > "$OUTPUT_DIR/secrets_output.json"

# SAST Agent
if [ "$ENABLE_SAST" = "true" ]; then
    echo "Running SAST Agent..."

    cat > "$OUTPUT_DIR/sast_input.json" << EOF
{
  "project_path": "$TEST_PROJECT",
  "config": $(cat "$OUTPUT_DIR/context_output.json" | jq '.agent_config.sast')
}
EOF

    call_agent \
        "agents/sast_agent" \
        "analyze_code" \
        "$OUTPUT_DIR/sast_input.json" \
        "$OUTPUT_DIR/sast_output.json" &
    SAST_PID=$!
fi

# SCA Agent
if [ "$ENABLE_SCA" = "true" ]; then
    echo "Running SCA Agent..."

    cat > "$OUTPUT_DIR/sca_input.json" << EOF
{
  "project_path": "$TEST_PROJECT",
  "config": $(cat "$OUTPUT_DIR/context_output.json" | jq '.agent_config.sca')
}
EOF

    call_agent \
        "agents/sca_agent" \
        "analyze_dependencies" \
        "$OUTPUT_DIR/sca_input.json" \
        "$OUTPUT_DIR/sca_output.json" &
    SCA_PID=$!
fi

# Secrets Agent
if [ "$ENABLE_SECRETS" = "true" ]; then
    echo "Running Secrets Agent..."

    cat > "$OUTPUT_DIR/secrets_input.json" << EOF
{
  "project_path": "$TEST_PROJECT",
  "config": $(cat "$OUTPUT_DIR/context_output.json" | jq '.agent_config.secrets')
}
EOF

    call_agent \
        "agents/secrets_agent" \
        "scan_secrets" \
        "$OUTPUT_DIR/secrets_input.json" \
        "$OUTPUT_DIR/secrets_output.json" &
    SECRETS_PID=$!
fi

# Wait for all agents to complete
echo "Waiting for scanning agents to complete..."
wait

echo -e "${GREEN}✓${NC} All scanning agents completed"
echo ""

# Show results summary
if [ "$ENABLE_SAST" = "true" ] && [ -s "$OUTPUT_DIR/sast_output.json" ]; then
    SAST_COUNT=$(cat "$OUTPUT_DIR/sast_output.json" | jq '.findings | length' 2>/dev/null || echo "0")
    echo "  SAST findings: $SAST_COUNT"
fi

if [ "$ENABLE_SCA" = "true" ] && [ -s "$OUTPUT_DIR/sca_output.json" ]; then
    SCA_COUNT=$(cat "$OUTPUT_DIR/sca_output.json" | jq '.findings | length' 2>/dev/null || echo "0")
    echo "  SCA findings: $SCA_COUNT"
fi

if [ "$ENABLE_SECRETS" = "true" ] && [ -s "$OUTPUT_DIR/secrets_output.json" ]; then
    SECRETS_COUNT=$(cat "$OUTPUT_DIR/secrets_output.json" | jq '.findings | length' 2>/dev/null || echo "0")
    echo "  Secrets findings: $SECRETS_COUNT"
fi

echo ""

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 4: Aggregator Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "Consolidating and deduplicating findings..."

cat > "$OUTPUT_DIR/aggregator_input.json" << EOF
{
  "sast_findings": $(cat "$OUTPUT_DIR/sast_output.json" | jq '.findings'),
  "sca_findings": $(cat "$OUTPUT_DIR/sca_output.json" | jq '.findings'),
  "secrets_findings": $(cat "$OUTPUT_DIR/secrets_output.json" | jq '.findings'),
  "project_profile": $(cat "$OUTPUT_DIR/profiler_output.json"),
  "project_context": $(cat "$OUTPUT_DIR/context_output.json" | jq '.project_context'),
  "config": {
    "enable_deduplication": true,
    "deduplication_strategy": "exact"
  }
}
EOF

call_agent \
    "agents/aggregator_agent" \
    "aggregate_findings" \
    "$OUTPUT_DIR/aggregator_input.json" \
    "$OUTPUT_DIR/aggregator_output.json"

if [ -s "$OUTPUT_DIR/aggregator_output.json" ] && [ "$(cat $OUTPUT_DIR/aggregator_output.json)" != "null" ]; then
    echo -e "${GREEN}✓${NC} Aggregator agent completed successfully"
    echo ""
    echo "Aggregated Report Summary:"
    cat "$OUTPUT_DIR/aggregator_output.json" | jq '{
        total_findings: .summary.total_findings,
        unique_findings: .summary.unique_findings,
        duplicates_removed: .summary.duplicates_removed,
        by_severity: .summary | {critical: .critical_findings, high: .high_findings, medium: .medium_findings, low: .low_findings},
        risk_score: .summary.risk_score
    }'
    echo ""
else
    echo -e "${RED}✗${NC} Aggregator agent failed"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 5: Remediation Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "Generating remediation plans..."

cat > "$OUTPUT_DIR/remediation_input.json" << EOF
{
  "aggregated_report": $(cat "$OUTPUT_DIR/aggregator_output.json"),
  "project_profile": $(cat "$OUTPUT_DIR/profiler_output.json"),
  "project_context": $(cat "$OUTPUT_DIR/context_output.json" | jq '.project_context'),
  "config": {
    "generate_alternatives": true,
    "max_alternatives": 2,
    "include_tests": true,
    "detailed_steps": true,
    "estimate_complexity": true
  }
}
EOF

call_agent \
    "agents/remediation_agent" \
    "generate_remediation_plans" \
    "$OUTPUT_DIR/remediation_input.json" \
    "$OUTPUT_DIR/remediation_output.json"

if [ -s "$OUTPUT_DIR/remediation_output.json" ] && [ "$(cat $OUTPUT_DIR/remediation_output.json)" != "null" ]; then
    echo -e "${GREEN}✓${NC} Remediation agent completed successfully"
    echo ""
    echo "Remediation Summary:"
    cat "$OUTPUT_DIR/remediation_output.json" | jq '{
        total_plans: (.remediation_plans | length),
        by_complexity: .summary.by_complexity,
        estimated_total_time: .summary.estimated_total_time
    }'
    echo ""
else
    echo -e "${RED}✗${NC} Remediation agent failed"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}STEP 6: Report Agent${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo "Generating final reports..."

cat > "$OUTPUT_DIR/report_input.json" << EOF
{
  "aggregated_report": $(cat "$OUTPUT_DIR/aggregator_output.json"),
  "remediation_plans": $(cat "$OUTPUT_DIR/remediation_output.json" | jq '.remediation_plans'),
  "project_profile": $(cat "$OUTPUT_DIR/profiler_output.json"),
  "config": {
    "formats": ["json", "html", "markdown"],
    "output_dir": "$OUTPUT_DIR",
    "include_executive_summary": true
  }
}
EOF

call_agent \
    "agents/report_agent" \
    "generate_reports" \
    "$OUTPUT_DIR/report_input.json" \
    "$OUTPUT_DIR/report_output.json"

if [ -s "$OUTPUT_DIR/report_output.json" ] && [ "$(cat $OUTPUT_DIR/report_output.json)" != "null" ]; then
    echo -e "${GREEN}✓${NC} Report agent completed successfully"
    echo ""
    echo "Generated Reports:"
    cat "$OUTPUT_DIR/report_output.json" | jq -r '.reports | keys[]' | while read format; do
        echo "  - $format report generated"
    done
    echo ""
else
    echo -e "${RED}✗${NC} Report agent failed"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ PIPELINE INTEGRATION TEST COMPLETED SUCCESSFULLY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo "Pipeline Summary:"
echo "  1. ✓ Profiler Agent"
echo "  2. ✓ Contextualization Agent"
echo "  3. ✓ Security Scanning Agents (SAST/SCA/Secrets)"
echo "  4. ✓ Aggregator Agent"
echo "  5. ✓ Remediation Agent"
echo "  6. ✓ Report Agent"
echo ""

echo "Output files available in: $OUTPUT_DIR"
echo ""

# Show key metrics
echo "═══════════════════════════════════════════════════════════════"
echo "FINAL RESULTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

TOTAL_FINDINGS=$(cat "$OUTPUT_DIR/aggregator_output.json" | jq '.summary.total_findings')
UNIQUE_FINDINGS=$(cat "$OUTPUT_DIR/aggregator_output.json" | jq '.summary.unique_findings')
CRITICAL_FINDINGS=$(cat "$OUTPUT_DIR/aggregator_output.json" | jq '.summary.critical_findings')
HIGH_FINDINGS=$(cat "$OUTPUT_DIR/aggregator_output.json" | jq '.summary.high_findings')
RISK_SCORE=$(cat "$OUTPUT_DIR/aggregator_output.json" | jq '.summary.risk_score')
REMEDIATION_PLANS=$(cat "$OUTPUT_DIR/remediation_output.json" | jq '.remediation_plans | length')

echo "Findings:"
echo "  Total: $TOTAL_FINDINGS"
echo "  Unique: $UNIQUE_FINDINGS"
echo "  Critical: $CRITICAL_FINDINGS"
echo "  High: $HIGH_FINDINGS"
echo ""
echo "Risk Score: $RISK_SCORE/100"
echo "Remediation Plans: $REMEDIATION_PLANS"
echo ""

echo -e "${GREEN}All agents executed successfully!${NC}"
echo -e "${GREEN}Full pipeline test: PASSED ✓${NC}"
echo ""
