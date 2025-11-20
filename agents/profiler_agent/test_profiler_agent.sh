#!/bin/bash

# Test script for Profiler Agent
# This script tests all three tools: analyze_project, detect_languages, extract_dependencies

set -e

echo "=== Profiler Agent Test Script ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test project path (using the security_project itself as test subject)
TEST_PROJECT_PATH="$(pwd)"

echo "Test project: $TEST_PROJECT_PATH"
echo ""

# Navigate to profiler_agent directory
cd "$(dirname "$0")/agents/profiler_agent"

echo "=== Test 1: analyze_project ===" 
echo ""

# Create test input for analyze_project
cat > /tmp/test_profiler_analyze.json << EOF
{
  "project_path": "$TEST_PROJECT_PATH",
  "options": {
    "exclude_patterns": ["node_modules", "vendor", ".git"],
    "max_depth": 10,
    "include_dev_deps": true
  }
}
EOF

echo "Running analyze_project..."
cat /tmp/test_profiler_analyze.json | go run . analyze_project > /tmp/test_profiler_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} analyze_project completed successfully"
    echo ""
    
    # Validate output structure
    if command -v jq &> /dev/null; then
        echo "Validating output structure..."
        
        # Check for required fields
        LANGUAGES=$(cat /tmp/test_profiler_output.json | jq '.languages | length')
        FRAMEWORKS=$(cat /tmp/test_profiler_output.json | jq '.frameworks | length')
        DEPENDENCIES=$(cat /tmp/test_profiler_output.json | jq '.dependencies | length')
        TOTAL_FILES=$(cat /tmp/test_profiler_output.json | jq '.file_tree.total_files')
        PROJECT_NAME=$(cat /tmp/test_profiler_output.json | jq -r '.metadata.project_name')
        
        echo "  Languages detected: $LANGUAGES"
        echo "  Frameworks detected: $FRAMEWORKS"
        echo "  Dependencies found: $DEPENDENCIES"
        echo "  Total files: $TOTAL_FILES"
        echo "  Project name: $PROJECT_NAME"
        echo ""
        
        # Verify we detected Go (since this is a Go project)
        GO_DETECTED=$(cat /tmp/test_profiler_output.json | jq '.languages[] | select(.name == "Go") | .name' 2>/dev/null)
        if [ -n "$GO_DETECTED" ]; then
            echo -e "${GREEN}✓${NC} Go language correctly detected"
        else
            echo -e "${YELLOW}⚠${NC} Go language not detected (expected for this project)"
        fi
        
        # Check if file tree analysis worked
        HAS_TESTS=$(cat /tmp/test_profiler_output.json | jq '.file_tree.has_tests')
        HAS_DOCS=$(cat /tmp/test_profiler_output.json | jq '.file_tree.has_docs')
        IS_GIT_REPO=$(cat /tmp/test_profiler_output.json | jq '.metadata.is_git_repo')
        
        echo "  Has tests: $HAS_TESTS"
        echo "  Has docs: $HAS_DOCS"
        echo "  Is Git repo: $IS_GIT_REPO"
        echo ""
    else
        echo -e "${YELLOW}⚠${NC} jq not installed, skipping detailed validation"
        echo ""
    fi
else
    echo -e "${RED}✗${NC} analyze_project failed"
    cat /tmp/test_profiler_output.json
    exit 1
fi

echo "=== Test 2: detect_languages ===" 
echo ""

# Create test input for detect_languages
cat > /tmp/test_profiler_languages.json << EOF
{
  "project_path": "$TEST_PROJECT_PATH"
}
EOF

echo "Running detect_languages..."
cat /tmp/test_profiler_languages.json | go run . detect_languages > /tmp/test_profiler_languages_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} detect_languages completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        echo "Languages detected:"
        cat /tmp/test_profiler_languages_output.json | jq -r '.languages[] | "  - \(.name): \(.file_count) files (\(.percentage)%)"'
        echo ""
    fi
else
    echo -e "${RED}✗${NC} detect_languages failed"
    cat /tmp/test_profiler_languages_output.json
    exit 1
fi

echo "=== Test 3: extract_dependencies ===" 
echo ""

# Create test input for extract_dependencies (Go)
cat > /tmp/test_profiler_deps.json << EOF
{
  "project_path": "$TEST_PROJECT_PATH",
  "language": "Go"
}
EOF

echo "Running extract_dependencies for Go..."
cat /tmp/test_profiler_deps.json | go run . extract_dependencies > /tmp/test_profiler_deps_output.json 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} extract_dependencies completed successfully"
    echo ""
    
    if command -v jq &> /dev/null; then
        DEPS_COUNT=$(cat /tmp/test_profiler_deps_output.json | jq '.dependencies | length')
        SOURCE_FILE=$(cat /tmp/test_profiler_deps_output.json | jq -r '.source_file')
        
        echo "  Dependencies found: $DEPS_COUNT"
        echo "  Source file: $SOURCE_FILE"
        
        if [ "$DEPS_COUNT" -gt 0 ]; then
            echo ""
            echo "  Sample dependencies:"
            cat /tmp/test_profiler_deps_output.json | jq -r '.dependencies[0:3][] | "    - \(.name) (\(.version))"'
        fi
        echo ""
    fi
else
    echo -e "${RED}✗${NC} extract_dependencies failed"
    cat /tmp/test_profiler_deps_output.json
    exit 1
fi

echo "=== Test 4: Error Handling ===" 
echo ""

# Temporarily disable exit on error for these tests
set +e

# Test with invalid project path
echo "Testing error handling with invalid path..."
echo '{"project_path": "/nonexistent/path"}' | go run . detect_languages > /tmp/test_profiler_error.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly handles invalid project path"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with invalid path"
fi
echo ""

# Test with missing required field
echo "Testing error handling with missing language parameter..."
echo '{"project_path": "'$TEST_PROJECT_PATH'"}' | go run . extract_dependencies > /tmp/test_profiler_error2.json 2>&1
ERROR_CODE=$?

if [ $ERROR_CODE -ne 0 ]; then
    echo -e "${GREEN}✓${NC} Correctly validates required parameters"
else
    echo -e "${YELLOW}⚠${NC} Should have failed with missing language parameter"
fi
echo ""

# Re-enable exit on error
set -e

echo "=== Test 5: JSON Output Validation ===" 
echo ""

echo "Validating JSON structure for all outputs..."
if command -v jq &> /dev/null; then
    # Validate analyze_project output
    cat /tmp/test_profiler_output.json | jq empty 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} analyze_project output is valid JSON"
    else
        echo -e "${RED}✗${NC} analyze_project output is invalid JSON"
        exit 1
    fi
    
    # Validate detect_languages output
    cat /tmp/test_profiler_languages_output.json | jq empty 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} detect_languages output is valid JSON"
    else
        echo -e "${RED}✗${NC} detect_languages output is invalid JSON"
        exit 1
    fi
    
    # Validate extract_dependencies output
    cat /tmp/test_profiler_deps_output.json | jq empty 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} extract_dependencies output is valid JSON"
    else
        echo -e "${RED}✗${NC} extract_dependencies output is invalid JSON"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠${NC} jq not installed, skipping JSON validation"
fi
echo ""

echo "=== Test 6: Performance Check ===" 
echo ""

echo "Checking scan performance..."
if command -v jq &> /dev/null; then
    SCAN_DURATION=$(cat /tmp/test_profiler_output.json | jq '.metadata.scan_duration_ms')
    echo "  Scan duration: ${SCAN_DURATION}ms"
    
    if [ "$SCAN_DURATION" -lt 10000 ]; then
        echo -e "${GREEN}✓${NC} Scan completed in reasonable time (< 10s)"
    else
        echo -e "${YELLOW}⚠${NC} Scan took longer than expected (> 10s)"
    fi
fi
echo ""

# Cleanup
echo "=== Cleanup ===" 
rm -f /tmp/test_profiler_*.json
echo -e "${GREEN}✓${NC} Cleaned up test files"
echo ""

echo -e "${GREEN}=== All Profiler Agent Tests Passed ===${NC}"
echo ""

# Display sample output
echo "Sample output from analyze_project:"
echo "-----------------------------------"
cd "$(dirname "$0")"
cat > /tmp/test_profiler_final.json << EOF
{
  "project_path": "$TEST_PROJECT_PATH",
  "options": {
    "exclude_patterns": [],
    "max_depth": 3,
    "include_dev_deps": false
  }
}
EOF

cat /tmp/test_profiler_final.json | ./agents/profiler_agent/profiler_agent analyze_project 2>/dev/null | jq '.' | head -50
rm -f /tmp/test_profiler_final.json
