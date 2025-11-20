package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func GenerateCodeFix(input CodeFixInput) (*CodeFixOutput, error) {
	fix, err := GenerateCodeFixFromFinding(input.Finding, input.ProjectContext)
	if err != nil {
		return nil, err
	}

	return &CodeFixOutput{
		Fix: fix,
	}, nil
}

func GenerateCodeFixFromFinding(finding map[string]interface{}, context map[string]interface{}) (Fix, error) {
	filePath := GetStringValue(finding, "file_path")
	lineNumber := GetIntValue(finding, "line_number")
	findingType := GetStringValue(finding, "type")
	category := GetStringValue(finding, "category")
	severity := GetStringValue(finding, "severity")
	description := GetStringValue(finding, "description")

	codeContext, _ := ExtractCodeContext(filePath, lineNumber, 30)
	lang := DetectLanguage(filePath)

	cweList := extractStringArray(finding, "cwe")
	owaspList := extractStringArray(finding, "owasp")

	frameworks := GetStringValue(context, "frameworks")
	projectType := GetStringValue(context, "type")

	prompt := fmt.Sprintf(`You are a security remediation expert. Generate a specific code fix for this vulnerability.

Vulnerability:
- Type: %s
- Category: %s
- Severity: %s
- File: %s
- Line: %d

Current Code:
%s

CWE: %s
OWASP: %s
Description: %s

Project Context:
- Language: %s
- Framework: %s
- Type: %s

Generate a SPECIFIC, WORKING code fix that:
1. Completely resolves the vulnerability
2. Maintains existing functionality
3. Follows best practices for %s
4. Is production-ready

Respond in JSON:
{
  "code_before": "exact current vulnerable code",
  "code_after": "fixed code with proper escaping/validation",
  "explanation": "why this fix works",
  "impact": "what changes functionally",
  "rationale": "security principles applied",
  "breaking_change": false
}

CRITICAL: The code_after must be complete, compilable, working code with proper imports if needed.`,
		findingType,
		category,
		severity,
		filePath,
		lineNumber,
		codeContext,
		strings.Join(cweList, ", "),
		strings.Join(owaspList, ", "),
		description,
		lang,
		frameworks,
		projectType,
		lang,
	)

	response, err := callOllama(prompt)
	if err != nil {
		return generateFallbackCodeFix(finding, lang), nil
	}

	var fixData struct {
		CodeBefore     string `json:"code_before"`
		CodeAfter      string `json:"code_after"`
		Explanation    string `json:"explanation"`
		Impact         string `json:"impact"`
		Rationale      string `json:"rationale"`
		BreakingChange bool   `json:"breaking_change"`
	}

	if err := json.Unmarshal([]byte(response), &fixData); err != nil {
		return generateFallbackCodeFix(finding, lang), nil
	}

	return Fix{
		Type:           "code-patch",
		Description:    fixData.Explanation,
		CodeBefore:     fixData.CodeBefore,
		CodeAfter:      fixData.CodeAfter,
		FilePath:       filePath,
		LineNumber:     lineNumber,
		Impact:         fixData.Impact,
		Rationale:      fixData.Rationale,
		BreakingChange: fixData.BreakingChange,
	}, nil
}

func generateFallbackCodeFix(finding map[string]interface{}, lang string) Fix {
	filePath := GetStringValue(finding, "file_path")
	lineNumber := GetIntValue(finding, "line_number")
	findingType := GetStringValue(finding, "type")

	codeBefore := fmt.Sprintf("// Vulnerable code at %s:%d", filePath, lineNumber)
	codeAfter := generateFixedCode(findingType, lang)
	impact := "Security improvement with minimal functional changes"
	rationale := generateRationale(findingType)

	if findingType == "sql-injection" {
		codeBefore = `db.Query("SELECT * FROM users WHERE id = " + userId)`
		codeAfter = `db.Query("SELECT * FROM users WHERE id = ?", userId)`
		rationale = "Parameterized queries prevent SQL injection by separating SQL code from data"
	}

	if findingType == "xss" {
		codeBefore = `html := "<div>" + userInput + "</div>"`
		codeAfter = `html := "<div>" + template.HTMLEscapeString(userInput) + "</div>"`
		rationale = "HTML escaping prevents XSS by neutralizing malicious scripts"
	}

	return Fix{
		Type:           "code-patch",
		Description:    fmt.Sprintf("Fix %s vulnerability in %s", findingType, filePath),
		CodeBefore:     codeBefore,
		CodeAfter:      codeAfter,
		FilePath:       filePath,
		LineNumber:     lineNumber,
		Impact:         impact,
		Rationale:      rationale,
		BreakingChange: false,
	}
}

func generateFixedCode(findingType, lang string) string {
	switch findingType {
	case "sql-injection":
		if lang == "go" {
			return `db.Query("SELECT * FROM users WHERE id = ?", userId)`
		}
		return `query("SELECT * FROM users WHERE id = ?", [userId])`
	case "xss":
		if lang == "go" {
			return `template.HTMLEscapeString(userInput)`
		}
		return `escapeHtml(userInput)`
	case "weak-crypto":
		if lang == "go" {
			return `bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)`
		}
		return `bcrypt.hash(password)`
	default:
		return "// Fixed code"
	}
}

func generateRationale(findingType string) string {
	rationales := map[string]string{
		"sql-injection":     "Parameterized queries prevent SQL injection by separating SQL code from data",
		"xss":               "Proper output encoding prevents XSS attacks by neutralizing malicious scripts",
		"weak-crypto":       "Strong cryptographic algorithms prevent password cracking",
		"path-traversal":    "Path validation prevents unauthorized file access",
		"command-injection": "Input validation and parameterization prevent command injection",
		"hardcoded-secret":  "Environment variables keep secrets out of source code",
	}

	if r, ok := rationales[findingType]; ok {
		return r
	}

	return "Security best practices recommend this approach"
}

func callOllama(prompt string) (string, error) {
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "codellama"
	}

	requestBody := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(ollamaURL+"/api/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func extractStringArray(m map[string]interface{}, key string) []string {
	var result []string

	if val, ok := m[key].([]interface{}); ok {
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}

	return result
}
