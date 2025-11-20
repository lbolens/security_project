# Testing Guide

This guide explains how to test the security analysis pipeline.

## Quick Start

### Test Report Agent

```bash
# Run the automated test script
./test_report_agent.sh
```

This will:
- Generate sample security findings
- Run the report agent
- Verify output files (JSON, HTML, Markdown)
- Check Ollama integration

## Manual Testing

### 1. Test Individual Agents

Each agent can be tested independently:

```bash
# Profiler Agent
cd agents/profiler_agent
echo '{"project_path": "/path/to/project"}' | go run . analyze_project

# SAST Agent
cd agents/sast_agent
echo '{"project_path": "/path/to/project", "languages": ["go"], "config": {"severity": "medium"}}' | go run . scan_project

# Report Agent
cd agents/report_agent
cat sample_input.json | go run . generate_reports
```

### 2. Test with Ollama

**Prerequisites:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull the model (in another terminal)
ollama pull codellama
```

**Set environment variables:**
```bash
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama
```

**Run Report Agent:**
```bash
cd agents/report_agent
cat sample_input.json | go run . generate_reports
```

The executive summary should now be AI-generated instead of showing the fallback message.

### 3. Test Report Formats

Create a test input file:

```json
{
  "aggregated_report": {
    "summary": {
      "total_findings": 3,
      "critical_findings": 1,
      "high_findings": 2,
      "risk_score": 75.0
    },
    "findings": [...]
  },
  "project_profile": {
    "metadata": {
      "project_name": "My Test Project"
    }
  },
  "config": {
    "formats": ["json", "html", "markdown", "pdf"],
    "output_dir": "./my-reports"
  }
}
```

Run:
```bash
cat test_input.json | go run agents/report_agent/main.go generate_reports
```

Check output:
```bash
ls -lh ./my-reports/
```

### 4. Test PDF Generation

**Install wkhtmltopdf:**
```bash
brew install wkhtmltopdf
```

**Generate PDF report:**
```bash
# Update config to include "pdf" format
cat test_input.json | go run agents/report_agent/main.go generate_reports
```

## Testing Checklist

- [ ] Report Agent builds successfully
- [ ] JSON reports generate correctly
- [ ] HTML reports generate correctly
- [ ] Markdown reports generate correctly
- [ ] PDF reports generate (if wkhtmltopdf installed)
- [ ] Ollama integration works (if Ollama running)
- [ ] Graceful degradation without Ollama
- [ ] Error handling for invalid input
- [ ] Multiple format generation in one run

## Common Issues

### "Ollama is not available"
**Solution:** This is expected if Ollama is not running. The agent will generate reports with a fallback message for the executive summary.

### "wkhtmltopdf not found"
**Solution:** PDF generation is optional. Install with `brew install wkhtmltopdf` or skip PDF format.

### "Module not found"
**Solution:** Run `go mod tidy` in the agent directory.

## Integration Testing

To test the full pipeline (when other agents are implemented):

```bash
# 1. Profile the project
profiler_output=$(echo '{"project_path": "./test-project"}' | go run agents/profiler_agent/main.go analyze_project)

# 2. Contextualize
context_output=$(echo "$profiler_output" | go run agents/contextualization_agent/main.go contextualize_analysis)

# 3. Run security scans (parallel)
sast_output=$(echo "$context_output" | go run agents/sast_agent/main.go scan_project)
sca_output=$(echo "$context_output" | go run agents/sca_agent/main.go scan_dependencies)
secrets_output=$(echo "$context_output" | go run agents/secrets_agent/main.go scan_secrets)

# 4. Aggregate findings
aggregated=$(echo '{"sast_findings": '$sast_output', ...}' | go run agents/aggregator_agent/main.go aggregate_findings)

# 5. Generate remediation
remediation=$(echo "$aggregated" | go run agents/remediation_agent/main.go generate_remediation_plans)

# 6. Generate reports
echo "$remediation" | go run agents/report_agent/main.go generate_reports
```

## Performance Testing

```bash
# Time the report generation
time cat large_input.json | go run agents/report_agent/main.go generate_reports

# Check memory usage
/usr/bin/time -l go run agents/report_agent/main.go generate_reports < large_input.json
```

## Debugging

Enable verbose output:
```bash
# Add debug logging to report.go
# Run with stderr visible
cat test_input.json | go run . generate_reports 2>&1 | tee debug.log
```
