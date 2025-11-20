# Quick Testing Guide

## 🚀 Quick Start

```bash
# Run automated test
./test_report_agent.sh
```

## 📝 Manual Testing

### Test Report Agent

```bash
cd agents/report_agent

# Create test input
cat > input.json << 'EOF'
{
  "aggregated_report": {
    "summary": {
      "total_findings": 2,
      "critical_findings": 1,
      "high_findings": 1,
      "risk_score": 85.5
    },
    "findings": [
      {
        "id": "FIND-001",
        "title": "SQL Injection",
        "severity": "CRITICAL",
        "category": "SAST",
        "file_path": "src/db.go",
        "line_number": 45,
        "priority": 1,
        "description": "User input concatenated into SQL query.",
        "owasp": ["A03:2021-Injection"],
        "cwe": ["CWE-89"]
      }
    ],
    "statistics": {
      "by_category": {"SAST": 1}
    }
  },
  "remediation_plans": [],
  "project_profile": {
    "metadata": {
      "project_name": "Test Project"
    }
  },
  "project_context": {},
  "config": {
    "formats": ["json", "html", "markdown"],
    "output_dir": "./reports",
    "include_executive_summary": true
  }
}
EOF

# Run the agent
cat input.json | go run . generate_reports

# Check output
ls -lh ./reports/
cat ./reports/*.json | jq '.summary'
```

## 🤖 Test with Ollama (Optional)

If you want to test the AI-powered executive summary:

**macOS Installation:**
```bash
# Install Ollama via Homebrew
brew install ollama

# Start service (in separate terminal)
ollama serve

# Pull model (this will download ~3.8GB, takes 10-15 minutes)
ollama pull codellama

# Set env vars and test
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama
./test_report_agent.sh
```

**Linux Installation:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start service
ollama serve

# Pull model
ollama pull codellama

# Set env vars and test
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=codellama
cat input.json | go run . generate_reports
```

## 📊 Expected Output

```json
{
  "reports": {
    "json": "./reports/security-report-TIMESTAMP.json",
    "html": "./reports/security-report-TIMESTAMP.html",
    "markdown": "./reports/security-report-TIMESTAMP.markdown"
  },
  "metadata": {
    "generated_at": "2025-11-19T23:25:02+01:00",
    "project_name": "Test Project",
    "formats": ["json", "html", "markdown"]
  },
  "summary": {
    "total_findings": 2,
    "risk_score": 85.5,
    "risk_level": "high",
    "files_generated": 3
  }
}
```

## 🔍 Verify Results

```bash
# Check JSON structure
cat ./reports/*.json | jq '.'

# View HTML in browser
open ./reports/*.html

# Read Markdown
cat ./reports/*.markdown
```

## ⚙️ Test Other Agents

```bash
# Profiler Agent
cd agents/profiler_agent
echo '{"project_path": "."}' | go run . analyze_project

# SAST Agent
cd agents/sast_agent
echo '{"project_path": ".", "languages": ["go"], "config": {"severity": "medium"}}' | go run . scan_project
```

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Ollama is not available" | Expected if Ollama not running. Reports still generate with fallback message. |
| "wkhtmltopdf not found" | Install: `brew install wkhtmltopdf` or skip PDF format |
| Module errors | Run `go mod tidy` in agent directory |

## 📚 Full Documentation

See [TESTING.md](./TESTING.md) for comprehensive testing guide.
