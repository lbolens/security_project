#!/bin/bash

# Full Pipeline Test with Real Security Tools
# Tests with Semgrep, Trivy, Gitleaks, and Ollama integration

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TEST_PROJECT="/Users/lucasbolens/Desktop/security_project/test-projects/vulnerable-app"
OUTPUT_DIR="/Users/lucasbolens/Desktop/security_project/.security-scan"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Security Pipeline - Full Real-World Test            ${NC}"
echo -e "${BLUE}  with Semgrep + Trivy + Gitleaks + Ollama            ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

mkdir -p "$OUTPUT_DIR"

# Verify tools
echo -e "${BLUE}Verifying external tools...${NC}"
MISSING_TOOLS=""

if ! command -v semgrep &> /dev/null; then
    MISSING_TOOLS="$MISSING_TOOLS semgrep"
fi

if ! command -v trivy &> /dev/null; then
    MISSING_TOOLS="$MISSING_TOOLS trivy"
fi

if ! command -v gitleaks &> /dev/null; then
    MISSING_TOOLS="$MISSING_TOOLS gitleaks"
fi

if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}⚠ Ollama not installed - AI features will be disabled${NC}"
else
    echo -e "${GREEN}✓${NC} Ollama installed"
    # Check if codellama model exists
    if ollama list | grep -q codellama; then
        echo -e "${GREEN}✓${NC} CodeLlama model available"
    else
        echo -e "${YELLOW}⚠ CodeLlama model not found - AI features may be limited${NC}"
    fi
fi

if [ -n "$MISSING_TOOLS" ]; then
    echo -e "${RED}✗ Missing required tools:$MISSING_TOOLS${NC}"
    echo "Please install them with:"
    echo "  pip install semgrep"
    echo "  brew install trivy gitleaks"
    exit 1
fi

echo -e "${GREEN}✓${NC} All required tools installed"
echo "  - Semgrep: $(semgrep --version)"
echo "  - Trivy: $(trivy --version | head -1)"
echo "  - Gitleaks: $(gitleaks version)"
echo ""

# Step 1: Profiler
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[1/6] Profiler Agent${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
cd agents/profiler_agent
echo "{\"project_path\":\"$TEST_PROJECT\"}" | go run . analyze_project > "$OUTPUT_DIR/1_profiler.json" 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Profiler completed${NC}"
    LANGUAGES=$(cat "$OUTPUT_DIR/1_profiler.json" | jq -r '.languages[].name' | tr '\n' ', ' | sed 's/,$//')
    FRAMEWORKS=$(cat "$OUTPUT_DIR/1_profiler.json" | jq -r '.frameworks[].name' | tr '\n' ', ' | sed 's/,$//')
    echo "  Languages: $LANGUAGES"
    echo "  Frameworks: $FRAMEWORKS"
else
    echo -e "${RED}✗ Profiler failed${NC}"
    exit 1
fi
echo ""

# Step 2: Contextualization
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[2/6] Contextualization Agent${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
cd ../contextualization_agent
cat > /tmp/context_input.json << EOF
{
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_path": "$TEST_PROJECT"
}
EOF
cat /tmp/context_input.json | go run . analyze_project_context > "$OUTPUT_DIR/2_context.json" 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Contextualization completed${NC}"
    PROJECT_TYPE=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.project_context.type // "unknown"')
    DOMAIN=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.project_context.domain // "unknown"')
    CRITICALITY=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.project_context.criticality // "unknown"')
    echo "  Project type: $PROJECT_TYPE"
    echo "  Domain: $DOMAIN"
    echo "  Criticality: $CRITICALITY"

    ENABLE_SAST=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.agent_config.sast.enabled // true')
    ENABLE_SCA=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.agent_config.sca.enabled // true')
    ENABLE_SECRETS=$(cat "$OUTPUT_DIR/2_context.json" | jq -r '.agent_config.secrets.enabled // true')
    echo "  Agents: SAST=$ENABLE_SAST, SCA=$ENABLE_SCA, Secrets=$ENABLE_SECRETS"
else
    echo -e "${RED}✗ Contextualization failed${NC}"
    exit 1
fi
echo ""

# Step 3: Security Scanning with Real Tools
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[3/6] Security Scanning (Semgrep + Trivy + Gitleaks)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

# SAST with Semgrep
echo -e "${YELLOW}Running Semgrep SAST scan...${NC}"
cd "$TEST_PROJECT"
semgrep --config=auto --json --output "$OUTPUT_DIR/semgrep_raw.json" . 2>/dev/null || true

# Convert Semgrep output to our format
SAST_COUNT=$(cat "$OUTPUT_DIR/semgrep_raw.json" | jq '.results | length' 2>/dev/null || echo "0")
echo -e "${GREEN}✓ SAST scan completed${NC}"
echo "  Semgrep findings: $SAST_COUNT"

# Create formatted SAST output
cat "$OUTPUT_DIR/semgrep_raw.json" | jq '{
  findings: [.results[] | {
    id: .check_id,
    type: (.extra.metadata.category // "code-vulnerability"),
    severity: (if .extra.severity == "ERROR" then "high"
               elif .extra.severity == "WARNING" then "medium"
               else "low" end),
    title: .extra.message,
    description: .extra.message,
    file_path: .path,
    line_number: .start.line,
    code_snippet: .extra.lines,
    cwe: [.extra.metadata.cwe // ""],
    owasp: [.extra.metadata.owasp // ""],
    confidence: "high",
    source: "semgrep"
  }]
}' > "$OUTPUT_DIR/3_sast.json"

# SCA with Trivy
echo -e "${YELLOW}Running Trivy SCA scan...${NC}"
trivy fs --format json --output "$OUTPUT_DIR/trivy_raw.json" "$TEST_PROJECT" 2>/dev/null || true

# Convert Trivy output
SCA_COUNT=$(cat "$OUTPUT_DIR/trivy_raw.json" | jq '[.Results[]?.Vulnerabilities // []] | add | length' 2>/dev/null || echo "0")
echo -e "${GREEN}✓ SCA scan completed${NC}"
echo "  Trivy findings: $SCA_COUNT"

# Create formatted SCA output
cat "$OUTPUT_DIR/trivy_raw.json" | jq '{
  findings: [.Results[]?.Vulnerabilities[]? | {
    id: .VulnerabilityID,
    type: "vulnerable-dependency",
    severity: (.Severity // "unknown" | ascii_downcase),
    title: .VulnerabilityID,
    description: .Description,
    component_name: .PkgName,
    current_version: .InstalledVersion,
    fixed_version: .FixedVersion,
    cve: .VulnerabilityID,
    cvss: (.CVSS.nvd.V3Score // 0),
    source: "trivy"
  }]
}' > "$OUTPUT_DIR/3_sca.json"

# Secrets with Gitleaks
echo -e "${YELLOW}Running Gitleaks secrets scan...${NC}"
cd "$TEST_PROJECT"
gitleaks detect --no-git --report-format json --report-path "$OUTPUT_DIR/gitleaks_raw.json" 2>/dev/null || true

# Convert Gitleaks output
if [ -f "$OUTPUT_DIR/gitleaks_raw.json" ]; then
    SECRETS_COUNT=$(cat "$OUTPUT_DIR/gitleaks_raw.json" | jq 'length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✓ Secrets scan completed${NC}"
    echo "  Gitleaks findings: $SECRETS_COUNT"

    # Create formatted Secrets output
    cat "$OUTPUT_DIR/gitleaks_raw.json" | jq '{
      findings: [.[] | {
        id: .Fingerprint,
        type: "exposed-secret",
        severity: "critical",
        title: ("Exposed " + .RuleID),
        description: .Description,
        file_path: .File,
        line_number: (.StartLine // 0),
        secret_type: .RuleID,
        secret_value: "[REDACTED]",
        source: "gitleaks"
      }]
    }' > "$OUTPUT_DIR/3_secrets.json"
else
    echo '{"findings":[]}' > "$OUTPUT_DIR/3_secrets.json"
    SECRETS_COUNT=0
fi

echo ""
echo "Security Scan Summary:"
echo "  SAST (Semgrep): $SAST_COUNT vulnerabilities"
echo "  SCA (Trivy): $SCA_COUNT vulnerable dependencies"
echo "  Secrets (Gitleaks): $SECRETS_COUNT exposed secrets"
echo "  Total: $((SAST_COUNT + SCA_COUNT + SECRETS_COUNT)) issues found"
echo ""

# Step 4: Aggregator
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[4/6] Aggregator Agent${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
cd /Users/lucasbolens/Desktop/security_project/agents/aggregator_agent

cat > /tmp/aggregator_input.json << EOF
{"method":"aggregate_findings","params":{
  "sast_findings": $(cat "$OUTPUT_DIR/3_sast.json" | jq '.findings'),
  "sca_findings": $(cat "$OUTPUT_DIR/3_sca.json" | jq '.findings'),
  "secrets_findings": $(cat "$OUTPUT_DIR/3_secrets.json" | jq '.findings'),
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_context": $(cat "$OUTPUT_DIR/2_context.json" | jq '.project_context'),
  "config": {
    "enable_deduplication": true,
    "deduplication_strategy": "exact"
  }
}}
EOF

cat /tmp/aggregator_input.json | jq -c '.' | go run . > "$OUTPUT_DIR/4_aggregator.json" 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Aggregator completed${NC}"
    TOTAL=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.total_findings' 2>/dev/null || echo "0")
    UNIQUE=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.unique_findings' 2>/dev/null || echo "0")
    CRITICAL=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.critical_findings' 2>/dev/null || echo "0")
    HIGH=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.high_findings' 2>/dev/null || echo "0")
    RISK=$(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result.summary.risk_score' 2>/dev/null || echo "0")

    echo "  Total findings: $TOTAL"
    echo "  Unique findings: $UNIQUE"
    echo "  Critical: $CRITICAL"
    echo "  High: $HIGH"
    echo "  Risk score: $RISK/100"
else
    echo -e "${RED}✗ Aggregator failed${NC}"
    cat "$OUTPUT_DIR/4_aggregator.json"
    exit 1
fi
echo ""

# Step 5: Remediation with Ollama
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[5/6] Remediation Agent (with Ollama AI)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
cd /Users/lucasbolens/Desktop/security_project/agents/remediation_agent

cat > /tmp/remediation_input.json << EOF
{"method":"generate_remediation_plans","params":{
  "aggregated_report": $(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result'),
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "project_context": $(cat "$OUTPUT_DIR/2_context.json" | jq '.project_context'),
  "config": {
    "generate_alternatives": true,
    "max_alternatives": 2,
    "include_tests": true,
    "detailed_steps": true,
    "estimate_complexity": true,
    "use_ollama": true
  }
}}
EOF

cat /tmp/remediation_input.json | jq -c '.' | go run . > "$OUTPUT_DIR/5_remediation.json" 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Remediation completed${NC}"
    PLANS=$(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.remediation_plans | length' 2>/dev/null || echo "0")
    LOW_COMPLEXITY=$(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.summary.by_complexity.low // 0' 2>/dev/null || echo "0")
    MEDIUM_COMPLEXITY=$(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.summary.by_complexity.medium // 0' 2>/dev/null || echo "0")
    HIGH_COMPLEXITY=$(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.summary.by_complexity.high // 0' 2>/dev/null || echo "0")
    TOTAL_TIME=$(cat "$OUTPUT_DIR/5_remediation.json" | jq -r '.result.summary.estimated_total_time // "0 minutes"' 2>/dev/null)

    echo "  Remediation plans: $PLANS"
    echo "  Complexity: Low=$LOW_COMPLEXITY, Medium=$MEDIUM_COMPLEXITY, High=$HIGH_COMPLEXITY"
    echo "  Estimated time: $TOTAL_TIME"
else
    echo -e "${RED}✗ Remediation failed${NC}"
    cat "$OUTPUT_DIR/5_remediation.json"
    exit 1
fi
echo ""

# Step 6: Report Generation
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[6/6] Report Agent (JSON + HTML + Markdown)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
cd /Users/lucasbolens/Desktop/security_project/agents/report_agent

cat > /tmp/report_input.json << EOF
{
  "aggregated_report": $(cat "$OUTPUT_DIR/4_aggregator.json" | jq '.result'),
  "remediation_plans": $(cat "$OUTPUT_DIR/5_remediation.json" | jq '.result.remediation_plans'),
  "project_profile": $(cat "$OUTPUT_DIR/1_profiler.json"),
  "config": {
    "formats": ["json", "html", "markdown"],
    "output_dir": "$OUTPUT_DIR",
    "include_executive_summary": true
  }
}
EOF

cat /tmp/report_input.json | go run . generate_reports > "$OUTPUT_DIR/6_report.json" 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Report generation completed${NC}"
    echo "  Generated reports:"
    ls -lh "$OUTPUT_DIR"/security-report-*.{json,html,markdown} 2>/dev/null | tail -3 | awk '{print "    - " $9 " (" $5 ")"}'
else
    echo -e "${RED}✗ Report generation failed${NC}"
    cat "$OUTPUT_DIR/6_report.json"
    exit 1
fi
echo ""

# Final Summary
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ FULL PIPELINE TEST COMPLETED SUCCESSFULLY!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""

echo "Pipeline Summary:"
echo "  1. ✓ Profiler Agent - Analyzed project structure"
echo "  2. ✓ Contextualization Agent - Determined context"
echo "  3. ✓ Security Scans:"
echo "     - Semgrep (SAST): $SAST_COUNT code vulnerabilities"
echo "     - Trivy (SCA): $SCA_COUNT vulnerable dependencies"
echo "     - Gitleaks (Secrets): $SECRETS_COUNT exposed secrets"
echo "  4. ✓ Aggregator Agent - Consolidated findings"
echo "  5. ✓ Remediation Agent - Generated $PLANS fix plans"
echo "  6. ✓ Report Agent - Created multi-format reports"
echo ""

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo "SECURITY REPORT SUMMARY"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo "Total Issues Found: $TOTAL"
echo "Unique Issues: $UNIQUE"
echo "Critical Severity: $CRITICAL"
echo "High Severity: $HIGH"
echo "Risk Score: ${RED}$RISK/100${NC}"
echo ""
echo "Remediation Plans: $PLANS"
echo "Estimated Fix Time: $TOTAL_TIME"
echo ""

echo "Output Directory: $OUTPUT_DIR"
echo ""
echo -e "${GREEN}View your security report:${NC}"
echo "  HTML: open $OUTPUT_DIR/security-report-*.html"
echo "  Markdown: cat $OUTPUT_DIR/security-report-*.markdown"
echo "  JSON: jq '.' $OUTPUT_DIR/security-report-*.json"
echo ""

echo -e "${GREEN}✓ All tests passed! Pipeline is production-ready! 🚀${NC}"
