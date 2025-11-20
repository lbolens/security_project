package main

import (
	"encoding/json"
	"fmt"
)

func GenerateTests(input TestsInput) (*TestsOutput, error) {
	finding := input.Finding
	fix := input.Fix

	findingType := GetStringValue(finding, "type")
	fixType := GetStringValue(fix, "type")
	filePath := GetStringValue(finding, "file_path")
	lang := DetectLanguage(filePath)
	fixDescription := GetStringValue(fix, "description")

	prompt := fmt.Sprintf(`Generate test steps to verify this security fix works correctly.

Vulnerability Type: %s
Fix Type: %s
Language: %s

Fix Description:
%s

Generate:
1. Unit tests to verify the vulnerability is fixed
2. Integration tests if needed
3. Manual testing steps
4. Regression tests to ensure nothing broke

For each test, provide:
- Test type (unit/integration/manual/regression)
- Description of what to test
- Command to run (if automated)
- Expected result

Respond in JSON:
{
  "tests": [
    {
      "type": "unit",
      "description": "Test description",
      "command": "pytest test_file.py::test_function",
      "expected_result": "All tests pass, vulnerability no longer exploitable"
    }
  ]
}`,
		findingType,
		fixType,
		lang,
		fixDescription,
	)

	response, err := callOllama(prompt)
	if err != nil {
		return generateFallbackTests(finding, fix), nil
	}

	var testData struct {
		Tests []TestStep `json:"tests"`
	}

	if err := json.Unmarshal([]byte(response), &testData); err != nil {
		return generateFallbackTests(finding, fix), nil
	}

	return &TestsOutput{
		Tests: testData.Tests,
	}, nil
}

func generateFallbackTests(finding, fix map[string]interface{}) *TestsOutput {
	findingType := GetStringValue(finding, "type")
	fixType := GetStringValue(fix, "type")
	filePath := GetStringValue(finding, "file_path")
	lang := DetectLanguage(filePath)

	var tests []TestStep

	tests = append(tests, TestStep{
		Type:           "unit",
		Description:    fmt.Sprintf("Test that %s is fixed", findingType),
		Command:        generateUnitTestCommand(lang),
		ExpectedResult: "All tests pass, vulnerability is resolved",
	})

	if fixType == "code-patch" {
		tests = append(tests, TestStep{
			Type:           "manual",
			Description:    fmt.Sprintf("Attempt to exploit %s vulnerability", findingType),
			Command:        generateExploitCommand(findingType),
			ExpectedResult: "Exploit attempt is blocked or fails",
		})
	}

	if fixType == "dependency-update" {
		tests = append(tests, TestStep{
			Type:           "integration",
			Description:    "Verify application works with updated dependency",
			Command:        "make integration-test",
			ExpectedResult: "Integration tests pass, no regressions",
		})
	}

	tests = append(tests, TestStep{
		Type:           "regression",
		Description:    "Run full test suite to ensure no regressions",
		Command:        generateRegressionTestCommand(lang),
		ExpectedResult: "All tests pass, no new failures introduced",
	})

	return &TestsOutput{
		Tests: tests,
	}
}

func generateUnitTestCommand(lang string) string {
	switch lang {
	case "go":
		return "go test ./..."
	case "python":
		return "pytest tests/"
	case "javascript", "typescript":
		return "npm test"
	case "java":
		return "mvn test"
	default:
		return "make test"
	}
}

func generateRegressionTestCommand(lang string) string {
	switch lang {
	case "go":
		return "go test -v ./..."
	case "python":
		return "pytest tests/ -v"
	case "javascript", "typescript":
		return "npm run test:coverage"
	case "java":
		return "mvn verify"
	default:
		return "make test-all"
	}
}

func generateExploitCommand(findingType string) string {
	switch findingType {
	case "sql-injection":
		return "curl -X GET 'http://localhost:8080/users/1%27%20OR%20%271%27=%271'"
	case "xss":
		return "curl -X POST -d 'input=<script>alert(1)</script>' http://localhost:8080/comment"
	case "path-traversal":
		return "curl -X GET 'http://localhost:8080/file?path=../../../etc/passwd'"
	case "command-injection":
		return "curl -X POST -d 'cmd=ls;cat /etc/passwd' http://localhost:8080/exec"
	default:
		return "# Manual security testing required"
	}
}
