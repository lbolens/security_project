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
	IsActive       bool   `json:"is_active"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	Impact         string `json:"impact"`
	Recommendation string `json:"recommendation"`
}

type FindingInput struct {
	SecretType   string
	FilePath     string
	LineNumber   int
	Secret       string
	Entropy      float64
	Match        string
}

type ProjectContextInput struct {
	Type         string
	Domain       string
	IsProduction bool
}

func (c *OllamaClient) ValidateSecret(finding FindingInput, codeContext string, projectContext ProjectContextInput) (*ValidationResult, error) {
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

	return &validation, nil
}

func buildValidationPrompt(finding FindingInput, codeContext string, projectContext ProjectContextInput) string {
	return fmt.Sprintf(`You are a security expert. Analyze if this is a REAL active secret or a false positive.

Secret Detection:
- Type: %s
- File: %s
- Line: %d
- Redacted: %s
- Entropy: %.2f
- Match: %s

Code Context:
%s

Project Context:
- Type: %s
- Domain: %s
- Is Production: %v

Question: Is this likely an ACTIVE, REAL secret that poses a security risk?

Consider:
1. Is this a placeholder/example secret? (e.g., "YOUR_API_KEY_HERE", "xxx", "test123", "example", "dummy")
2. Is this in test/example files?
3. Is this commented out or unused?
4. Does the format match a real %s?
5. Is the entropy high enough to be real?
6. Is this in documentation/README?
7. Does the variable name suggest it's a placeholder (e.g., "example_key", "test_token")?

Respond ONLY with valid JSON in this exact format:
{
  "is_active": true,
  "confidence": "high",
  "reasoning": "detailed explanation",
  "impact": "what happens if exploited",
  "recommendation": "immediate actions"
}

NO other text, ONLY the JSON object.`,
		finding.SecretType,
		finding.FilePath,
		finding.LineNumber,
		finding.Secret,
		finding.Entropy,
		finding.Match,
		codeContext,
		projectContext.Type,
		projectContext.Domain,
		projectContext.IsProduction,
		finding.SecretType,
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
			marker = "→ "
		}
		context = append(context, fmt.Sprintf("%s%4d | %s", marker, lineNum, lines[i]))
	}

	return strings.Join(context, "\n"), nil
}
