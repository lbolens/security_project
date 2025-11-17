package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: contextualization_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: contextualize_analysis, get_agent_config, analyze_project_context\n")
		os.Exit(1)
	}

	toolName := os.Args[1]

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	var output interface{}

	switch toolName {
	case "contextualize_analysis":
		output, err = handleContextualizeAnalysis(input)
	case "get_agent_config":
		output, err = handleGetAgentConfig(input)
	case "analyze_project_context":
		output, err = handleAnalyzeProjectContext(input)
	default:
		fmt.Fprintf(os.Stderr, "Unknown tool: %s\n", toolName)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}

func handleContextualizeAnalysis(input []byte) (*AnalysisConfig, error) {
	var params ContextualizeAnalysisInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if len(params.ProjectProfile.Languages) == 0 {
		return nil, fmt.Errorf("project_profile.languages is required")
	}

	contextualizer := NewContextualizer()
	return contextualizer.ContextualizeAnalysis(params.ProjectProfile, params.Options)
}

func handleGetAgentConfig(input []byte) (*GetAgentConfigOutput, error) {
	var params GetAgentConfigInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.AgentName == "" {
		return nil, fmt.Errorf("agent_name is required")
	}

	contextualizer := NewContextualizer()
	config, err := contextualizer.GetAgentConfig(params.AgentName, params.ProjectProfile)
	if err != nil {
		return nil, err
	}

	return &GetAgentConfigOutput{
		AgentConfig: *config,
	}, nil
}

func handleAnalyzeProjectContext(input []byte) (*AnalyzeProjectContextOutput, error) {
	var params AnalyzeProjectContextInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	contextualizer := NewContextualizer()
	return contextualizer.AnalyzeProjectContext(params.ProjectProfile)
}
