package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: profiler_agent <tool_name>\n")
		fmt.Fprintf(os.Stderr, "Available tools: analyze_project, detect_languages, extract_dependencies\n")
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
	case "analyze_project":
		output, err = handleAnalyzeProject(input)
	case "detect_languages":
		output, err = handleDetectLanguages(input)
	case "extract_dependencies":
		output, err = handleExtractDependencies(input)
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

func handleAnalyzeProject(input []byte) (*ProjectProfile, error) {
	var params AnalyzeProjectInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	profiler := NewProfiler(
		params.Options.ExcludePatterns,
		params.Options.MaxDepth,
		params.Options.IncludeDevDeps,
	)

	return profiler.AnalyzeProject(params.ProjectPath)
}

func handleDetectLanguages(input []byte) (*DetectLanguagesOutput, error) {
	var params DetectLanguagesInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	profiler := NewProfiler([]string{}, 0, true)
	return profiler.DetectLanguages(params.ProjectPath)
}

func handleExtractDependencies(input []byte) (*ExtractDependenciesOutput, error) {
	var params ExtractDependenciesInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	if params.ProjectPath == "" {
		return nil, fmt.Errorf("project_path is required")
	}

	if params.Language == "" {
		return nil, fmt.Errorf("language is required")
	}

	profiler := NewProfiler([]string{}, 0, true)
	return profiler.ExtractDependencies(params.ProjectPath, params.Language)
}
