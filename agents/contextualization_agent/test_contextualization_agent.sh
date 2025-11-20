#!/bin/bash

# Test script for Contextualization Agent
# This script tests all three tools: contextualize_analysis, get_agent_config, analyze_project_context

set -e

echo "=== Contextualization Agent Test Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Navigate to contextualization_agent directory
cd "$(dirname "$0")/agents/contextualization_agent"

echo "=== Test 1: contextualize_analysis (Web API Project) ===" 
echo ""

# Create test input for a web API project
cat > /tmp/test_context_web.json << 'EOF'
{
  "project_profile": {
    "languages": [
      {
        "name": "Go",
        "file_count": 50,
        "percentage": 80.0
      },
      {
        "name": "JavaScript",
        "file_count": 12,
        "percentage": 20.0
      }
    ],
    "frameworks": [
      {
        "name": "Gin",
        "language": "Go"
      },
      {
        "name": "React",
        "language": "JavaScript"
      }
    ],
    "dependencies": [
      {
        "name": "github.com/gin-gonic/gin",
        "version": "v1.9.1",
        "language": "Go",
        "is_dev_dep": false
      }
    ],
    "file_tree": {
      "total_files": 62,
      "total_dirs": 10,
      "has_tests": true,
      "has_docs": true,
      "config_files": [".env", "config.yaml"]
    },
    "metadata": {
      "project_name": "test-api",
      "size_bytes": 1048576,
      "is_git_repo": true
    }
  },
  "options": {
    "force_all_agents": false,
    "severity_threshold": "medium",
    "use_ollama_analysis": false
  }
}
EOF

echo "Running contextualize_analysis for web API project..."
cat /tmp/test_context_web.json | go run . contextualize_analysis > /tmp/test_context_web_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} contextualize_analysis completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        echo "Analysis results:"
        ENABLED_AGENTS=$(cat /tmp/test_context_web_output.json | jq -r '.enabled_agents | join(", ")')
        PROJECT_TYPE=$(cat /tmp/test_context_web_output.json | jq -r '.project_context.type')
        CRITICALITY=$(cat /tmp/test_context_web_output.json | jq -r '.project_context.criticality')
        DOMAIN=$(cat /tmp/test_context_web_output.json | jq -r '.project_context.domain')
        
        echo "  Enabled agents: $ENABLED_AGENTS"
        echo "  Project type: $PROJECT_TYPE"
        echo "  Criticality: $CRITICALITY"
        echo "  Domain: $DOMAIN"
        
        # Check security concerns
        SECURITY_CONCERNS=$(cat /tmp/test_context_web_output.json | jq -r '.project_context.security_concerns | join(", ")')
        echo "  Security concerns: $SECURITY_CONCERNS"
        echo ""
        
        # Verify SAST is enabled for web project
        SAST_ENABLED=$(cat /tmp/test_context_web_output.json | jq -r '.agent_configs.sast.enabled')
        if [ "$SAST_ENABLED" = "true" ]; then
            echo -e "${GREEN}✓${NC} SAST correctly enabled for web project"
        else
            echo -e "${YELLOW}⚠${NC} SAST should be enabled for web project"
        fi
        
        # Verify SCA is enabled (has dependencies)
        SCA_ENABLED=$(cat /tmp/test_context_web_output.json | jq -r '.agent_configs.sca.enabled')
        if [ "$SCA_ENABLED" = "true" ]; then
            echo -e "${GREEN}✓${NC} SCA correctly enabled (has dependencies)"
        else
            echo -e "${YELLOW}⚠${NC} SCA should be enabled when dependencies exist"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} contextualize_analysis failed"
    cat /tmp/test_context_web_output.json
    exit 1
fi

echo "=== Test 2: contextualize_analysis (CLI Project) ===" 
echo ""

# Create test input for a CLI project
cat > /tmp/test_context_cli.json << 'EOF'
{
  "project_profile": {
    "languages": [
      {
        "name": "Go",
        "file_count": 20,
        "percentage": 100.0
      }
    ],
    "frameworks": [],
    "dependencies": [],
    "file_tree": {
      "total_files": 20,
      "total_dirs": 3,
      "has_tests": false,
      "has_docs": true,
      "config_files": []
    },
    "metadata": {
      "project_name": "cli-tool",
      "size_bytes": 204800,
      "is_git_repo": true
    }
  },
  "options": {
    "force_all_agents": false,
    "severity_threshold": "high",
    "use_ollama_analysis": false
  }
}
EOF

echo "Running contextualize_analysis for CLI project..."
cat /tmp/test_context_cli.json | go run . contextualize_analysis > /tmp/test_context_cli_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} contextualize_analysis completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        PROJECT_TYPE=$(cat /tmp/test_context_cli_output.json | jq -r '.project_context.type')
        CRITICALITY=$(cat /tmp/test_context_cli_output.json | jq -r '.project_context.criticality')
        
        echo "  Project type: $PROJECT_TYPE"
        echo "  Criticality: $CRITICALITY"
        
        if [ "$PROJECT_TYPE" = "cli" ]; then
            echo -e "${GREEN}✓${NC} Correctly identified as CLI project"
        else
            echo -e "${YELLOW}⚠${NC} Expected CLI project type, got: $PROJECT_TYPE"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} contextualize_analysis failed for CLI project"
    exit 1
fi

echo "=== Test 3: get_agent_config ===" 
echo ""

# Create test input for get_agent_config
cat > /tmp/test_get_config.json << 'EOF'
{
  "agent_name": "sast",
  "project_profile": {
    "languages": [
      {
        "name": "JavaScript",
        "file_count": 100,
        "percentage": 100.0
      }
    ],
    "frameworks": [
      {
        "name": "Express",
        "language": "JavaScript"
      }
    ],
    "dependencies": [],
    "file_tree": {
      "total_files": 100,
      "total_dirs": 15,
      "has_tests": true,
      "has_docs": true,
      "config_files": []
    },
    "metadata": {
      "project_name": "express-app",
      "size_bytes": 512000,
      "is_git_repo": true
    }
  }
}
EOF

echo "Running get_agent_config for SAST..."
cat /tmp/test_get_config.json | go run . get_agent_config > /tmp/test_get_config_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} get_agent_config completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        ENABLED=$(cat /tmp/test_get_config_output.json | jq -r '.agent_config.enabled')
        SEVERITY=$(cat /tmp/test_get_config_output.json | jq -r '.agent_config.severity')
        RULES_COUNT=$(cat /tmp/test_get_config_output.json | jq '.agent_config.rules | length')
        
        echo "  Enabled: $ENABLED"
        echo "  Severity: $SEVERITY"
        echo "  Rules count: $RULES_COUNT"
        
        if [ "$ENABLED" = "true" ]; then
            echo -e "${GREEN}✓${NC} SAST config correctly generated"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} get_agent_config failed"
    cat /tmp/test_get_config_output.json
    exit 1
fi

echo "=== Test 4: analyze_project_context ===" 
echo ""

# Create test input for analyze_project_context
cat > /tmp/test_analyze_context.json << 'EOF'
{
  "project_profile": {
    "languages": [
      {
        "name": "Solidity",
        "file_count": 15,
        "percentage": 100.0
      }
    ],
    "frameworks": [],
    "dependencies": [],
    "file_tree": {
      "total_files": 15,
      "total_dirs": 2,
      "has_tests": true,
      "has_docs": true,
      "config_files": ["hardhat.config.js"]
    },
    "metadata": {
      "project_name": "smart-contract",
      "size_bytes": 102400,
      "is_git_repo": true
    }
  }
}
EOF

echo "Running analyze_project_context for smart contract..."
cat /tmp/test_analyze_context.json | go run . analyze_project_context > /tmp/test_analyze_context_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} analyze_project_context completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        TYPE=$(cat /tmp/test_analyze_context_output.json | jq -r '.type')
        DOMAIN=$(cat /tmp/test_analyze_context_output.json | jq -r '.domain')
        CRITICALITY=$(cat /tmp/test_analyze_context_output.json | jq -r '.criticality')
        CONCERNS=$(cat /tmp/test_analyze_context_output.json | jq -r '.security_concerns | join(", ")')
        
        echo "  Type: $TYPE"
        echo "  Domain: $DOMAIN"
        echo "  Criticality: $CRITICALITY"
        echo "  Security concerns: $CONCERNS"
        
        if [ "$TYPE" = "smart-contract" ]; then
            echo -e "${GREEN}✓${NC} Correctly identified smart contract project"
        fi
        
        if [ "$CRITICALITY" = "critical" ] || [ "$CRITICALITY" = "high" ]; then
            echo -e "${GREEN}✓${NC} Correctly set high/critical criticality for smart contract"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} analyze_project_context failed"
    cat /tmp/test_analyze_context_output.json
    exit 1
fi

echo "=== Test 5: Force All Agents ===" 
echo ""

# Test with force_all_agents option
cat > /tmp/test_force_all.json << 'EOF'
{
  "project_profile": {
    "languages": [
      {
        "name": "Python",
        "file_count": 10,
        "percentage": 100.0
      }
    ],
    "frameworks": [],
    "dependencies": [],
    "file_tree": {
      "total_files": 10,
      "total_dirs": 2,
      "has_tests": false,
      "has_docs": false,
      "config_files": []
    },
    "metadata": {
      "project_name": "simple-script",
      "size_bytes": 10240,
      "is_git_repo": false
    }
  },
  "options": {
    "force_all_agents": true,
    "severity_threshold": "low",
    "use_ollama_analysis": false
  }
}
EOF

echo "Running contextualize_analysis with force_all_agents..."
cat /tmp/test_force_all.json | go run . contextualize_analysis > /tmp/test_force_all_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Force all agents test completed"
    echo ""
    
    if command -v jq &> /dev/null; then
        ENABLED_COUNT=$(cat /tmp/test_force_all_output.json | jq '.enabled_agents | length')
        ENABLED_AGENTS=$(cat /tmp/test_force_all_output.json | jq -r '.enabled_agents | join(", ")')
        
        echo "  Enabled agents count: $ENABLED_COUNT"
        echo "  Enabled agents: $ENABLED_AGENTS"
        
        if [ "$ENABLED_COUNT" -ge 2 ]; then
            echo -e "${GREEN}✓${NC} Multiple agents enabled with force_all_agents"
        else
            echo -e "${YELLOW}⚠${NC} Expected multiple agents with force_all_agents"
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} Force all agents test failed"
    exit 1
fi

echo "=== Test 6: Error Handling ===" 
echo ""

# Temporarily disable exit on error
set +e

# Test with missing required field
echo "Testing error handling with missing languages..."
echo '{"project_profile": {"languages": []}, "options": {}}' | go run . contextualize_analysis > /tmp/test_error.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly validates required fields"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with empty languages"
fi
echo ""

# Test with invalid agent name
echo "Testing error handling with invalid agent name..."
echo '{"agent_name": "invalid_agent", "project_profile": {"languages": [{"name": "Go", "file_count": 1, "percentage": 100}], "frameworks": [], "dependencies": [], "file_tree": {}, "metadata": {}}}' | go run . get_agent_config > /tmp/test_error2.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -eq 0 ]; then
    # Should return disabled config for unknown agent
    ENABLED=$(cat /tmp/test_error2.json | jq -r '.agent_config.enabled')
    if [ "$ENABLED" = "false" ]; then
        echo -e "${GREEN}✓${NC} Returns disabled config for unknown agent"
    fi
else
    echo -e "${YELLOW}⚠${NC} Unexpected error for unknown agent"
fi
echo ""

# Re-enable exit on error
set -e

echo "=== Test 7: JSON Output Validation ===" 
echo ""

echo "Validating JSON structure for all outputs..."
if command -v jq &> /dev/null; then
    # Validate all outputs
    for file in /tmp/test_context_web_output.json /tmp/test_context_cli_output.json /tmp/test_get_config_output.json /tmp/test_analyze_context_output.json /tmp/test_force_all_output.json; do
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
rm -f /tmp/test_context_*.json /tmp/test_get_config*.json /tmp/test_analyze_context*.json /tmp/test_force_all*.json /tmp/test_error*.json
echo -e "${GREEN}✓${NC} Cleaned up test files"
echo ""

echo -e "${GREEN}=== All Contextualization Agent Tests Passed ===${NC}"
echo ""

# Display sample output
echo "Sample output from contextualize_analysis:"
echo "-------------------------------------------"
cd "$(dirname "$0")"
cat > /tmp/test_final_context.json << 'EOF'
{
  "project_profile": {
    "languages": [{"name": "Go", "file_count": 50, "percentage": 100}],
    "frameworks": [{"name": "Gin", "language": "Go"}],
    "dependencies": [{"name": "gin", "version": "1.9.1", "language": "Go", "is_dev_dep": false}],
    "file_tree": {"total_files": 50, "total_dirs": 5, "has_tests": true, "has_docs": true, "config_files": []},
    "metadata": {"project_name": "sample", "size_bytes": 100000, "is_git_repo": true}
  },
  "options": {"force_all_agents": false, "severity_threshold": "medium", "use_ollama_analysis": false}
}
EOF

cat /tmp/test_final_context.json | ./agents/contextualization_agent/contextualization_agent contextualize_analysis 2>/dev/null | jq '.' | head -60
rm -f /tmp/test_final_context.json
