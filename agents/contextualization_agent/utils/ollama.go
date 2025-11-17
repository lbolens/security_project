package utils

import (
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

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type ProjectContext struct {
	Type             string   `json:"type"`
	Domain           string   `json:"domain"`
	Criticality      string   `json:"criticality"`
	SecurityConcerns []string `json:"security_concerns"`
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

func (c *OllamaClient) AnalyzeProjectContext(languages []string, frameworks []string, depsCount int, hasTests bool, configFiles []string) (*ProjectContext, error) {
	prompt := fmt.Sprintf(`Analyze this project and respond ONLY with valid JSON in this exact format:
{
  "type": "api|cli|library|smart-contract|frontend|backend|fullstack",
  "domain": "finance|healthcare|ecommerce|crypto|general|other",
  "criticality": "low|medium|high|critical",
  "security_concerns": ["concern1", "concern2"]
}

Project details:
- Languages: %s
- Frameworks: %s
- Dependencies count: %d
- Has tests: %v
- Config files: %v

Rules:
- type: Infer from frameworks and languages
- domain: Look for finance/crypto/healthcare keywords in frameworks
- criticality: high if web framework or many deps, medium otherwise
- security_concerns: List 2-4 relevant security concerns based on stack

Respond with ONLY the JSON object, no other text.`,
		strings.Join(languages, ", "),
		strings.Join(frameworks, ", "),
		depsCount,
		hasTests,
		configFiles,
	)

	response, err := c.Generate(prompt)
	if err != nil {
		return nil, err
	}

	var context ProjectContext
	if err := json.Unmarshal([]byte(response), &context); err != nil {
		cleanedResponse := extractJSON(response)
		if err := json.Unmarshal([]byte(cleanedResponse), &context); err != nil {
			return nil, fmt.Errorf("failed to parse Ollama response: %w", err)
		}
	}

	if context.Type == "" {
		context.Type = "unknown"
	}
	if context.Domain == "" {
		context.Domain = "general"
	}
	if context.Criticality == "" {
		context.Criticality = "medium"
	}

	return &context, nil
}

func (c *OllamaClient) Generate(prompt string) (string, error) {
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
