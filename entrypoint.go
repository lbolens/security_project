package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type Options struct {
	ExcludePatterns []string `json:"exclude_patterns"`
	MaxDepth        int      `json:"max_depth"`
	IncludeDevDeps  bool     `json:"include_dev_deps"`
}

type ProfilerInput struct {
	ProjectPath string  `json:"project_path"`
	Options     Options `json:"options"`
}

func main() {
	projectPath := flag.String("project-path", "", "Path to the project to analyze")
	flag.Parse()

	if *projectPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --project-path is required\n")
		os.Exit(1)
	}

	info, err := os.Stat(*projectPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: path does not exist: %s\n", *projectPath)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: cannot access path: %v\n", err)
		os.Exit(1)
	}

	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: path is not a directory: %s\n", *projectPath)
		os.Exit(1)
	}

	absPath, err := filepath.Abs(*projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot resolve absolute path: %v\n", err)
		os.Exit(1)
	}

	input := ProfilerInput{
		ProjectPath: absPath,
		Options: Options{
			ExcludePatterns: []string{},
			MaxDepth:        0,
			IncludeDevDeps:  true,
		},
	}

	output, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot marshal JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
