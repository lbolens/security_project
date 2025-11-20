package analyzer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type OllamaClient struct {
	URL   string
	Model string
}

func NewOllamaClient() *OllamaClient {
	url := os.Getenv("OLLAMA_URL")
	if url == "" {
		url = "http://localhost:11434"
	}

	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "codellama"
	}

	return &OllamaClient{
		URL:   url,
		Model: model,
	}
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type ValidationResult struct {
	IsVulnerable   bool   `json:"is_vulnerable"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	RiskLevel      string `json:"risk_level"`
	Exploitability string `json:"exploitability"`
}

func (c *OllamaClient) ValidateFinding(finding FindingInput, codeContext string, projectContext ProjectContextInput) (*ValidationResult, error) {
	prompt := buildValidationPrompt(finding, codeContext, projectContext)

	response, err := c.generate(prompt)
	if err != nil {
		return nil, err
	}

	var validation ValidationResult
	cleanedResponse := extractJSON(response)
	if err := json.Unmarshal([]byte(cleanedResponse), &validation); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	if validation.Confidence == "" {
		validation.Confidence = "medium"
	}
	if validation.RiskLevel == "" {
		validation.RiskLevel = "medium"
	}

	return &validation, nil
}

func buildValidationPrompt(finding FindingInput, codeContext string, projectContext ProjectContextInput) string {
	frameworks := strings.Join(projectContext.Frameworks, ", ")
	if frameworks == "" {
		frameworks = "none"
	}

	return fmt.Sprintf(`You are a security expert. Analyze if this is a REAL security vulnerability or a false positive.

Finding:
- Type: %s
- File: %s
- Line: %d
- Check ID: %s
- Severity: %s

Vulnerable Code:
%s

Extended Context (surrounding code):
%s

Project Context:
- Type: %s
- Domain: %s
- Frameworks: %s

Question: Is this a REAL %s vulnerability that can be exploited?

Consider:
1. Is user input actually involved?
2. Is the input properly validated/sanitized before this point?
3. Is this test code or dead code?
4. Are there security controls (auth, WAF, rate limiting)?
5. Can an attacker actually reach and exploit this code path?

Respond ONLY with valid JSON in this exact format:
{
  "is_vulnerable": true,
  "confidence": "high",
  "reasoning": "detailed explanation",
  "risk_level": "critical",
  "exploitability": "description of how it could be exploited"
}

NO other text, ONLY the JSON object.`,
		finding.Type,
		finding.FilePath,
		finding.LineNumber,
		finding.CheckID,
		"medium",
		finding.CodeSnippet,
		codeContext,
		projectContext.Type,
		projectContext.Domain,
		frameworks,
		finding.Type,
	)
}

func (c *OllamaClient) generate(prompt string) (string, error) {
	reqBody := OllamaRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(c.URL+"/api/generate", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

func extractJSON(text string) string {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return text[start : end+1]
	}
	return text
}

func ExtractCodeContext(filePath string, lineNumber int, contextLines int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := []string{}
	currentLine := 0

	for scanner.Scan() {
		currentLine++
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	start := lineNumber - contextLines - 1
	if start < 0 {
		start = 0
	}

	end := lineNumber + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	context := []string{}
	for i := start; i < end; i++ {
		lineNum := i + 1
		marker := "  "
		if lineNum == lineNumber {
			marker := "→ "
			context = append(context, fmt.Sprintf("%s%4d | %s", marker, lineNum, lines[i]))
		} else {
			context = append(context, fmt.Sprintf("%s%4d | %s", marker, lineNum, lines[i]))
		}
	}

	return strings.Join(context, "\n"), nil
}

type FindingInput struct {
	Type        string
	FilePath    string
	LineNumber  int
	CodeSnippet string
	CheckID     string
}

type ProjectContextInput struct {
	Type       string
	Domain     string
	Frameworks []string
}
