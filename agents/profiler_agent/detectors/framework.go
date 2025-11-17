package detectors

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Framework struct {
	Name     string
	Version  string
	Language string
}

var FrameworkPatterns = map[string]map[string]string{
	"JavaScript": {
		"react":   "React",
		"vue":     "Vue",
		"angular": "Angular",
		"express": "Express",
		"next":    "Next.js",
		"svelte":  "Svelte",
	},
	"TypeScript": {
		"react":   "React",
		"vue":     "Vue",
		"angular": "Angular",
		"express": "Express",
		"next":    "Next.js",
		"svelte":  "Svelte",
	},
	"Python": {
		"django":  "Django",
		"flask":   "Flask",
		"fastapi": "FastAPI",
	},
	"Go": {
		"gin-gonic/gin": "Gin",
		"gorilla/mux":   "Gorilla Mux",
		"gofiber/fiber": "Fiber",
		"labstack/echo": "Echo",
	},
	"Java": {
		"spring-boot": "Spring Boot",
		"quarkus":     "Quarkus",
		"micronaut":   "Micronaut",
	},
	"Solidity": {
		"hardhat": "Hardhat",
		"truffle": "Truffle",
		"foundry": "Foundry",
	},
}

func DetectFrameworks(projectPath string, languages []Language) ([]Framework, error) {
	frameworks := []Framework{}

	for _, lang := range languages {
		detected, err := detectForLanguage(projectPath, lang.Name)
		if err != nil {
			continue
		}
		frameworks = append(frameworks, detected...)
	}

	return frameworks, nil
}

func detectForLanguage(projectPath string, language string) ([]Framework, error) {
	switch language {
	case "JavaScript", "TypeScript":
		return detectJSFrameworks(projectPath, language)
	case "Python":
		return detectPythonFrameworks(projectPath)
	case "Go":
		return detectGoFrameworks(projectPath)
	case "Java":
		return detectJavaFrameworks(projectPath)
	case "Solidity":
		return detectSolidityFrameworks(projectPath)
	default:
		return []Framework{}, nil
	}
}

func detectJSFrameworks(projectPath string, language string) ([]Framework, error) {
	packageJSONPath := filepath.Join(projectPath, "package.json")
	file, err := os.Open(packageJSONPath)
	if err != nil {
		return []Framework{}, nil
	}
	defer file.Close()

	var packageJSON map[string]interface{}
	if err := json.NewDecoder(file).Decode(&packageJSON); err != nil {
		return []Framework{}, nil
	}

	frameworks := []Framework{}
	patterns := FrameworkPatterns[language]

	deps := make(map[string]string)
	if dependencies, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
		for name, version := range dependencies {
			if v, ok := version.(string); ok {
				deps[name] = v
			}
		}
	}
	if devDependencies, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
		for name, version := range devDependencies {
			if v, ok := version.(string); ok {
				deps[name] = v
			}
		}
	}

	for depName, version := range deps {
		for pattern, fwName := range patterns {
			if strings.Contains(depName, pattern) {
				frameworks = append(frameworks, Framework{
					Name:     fwName,
					Version:  strings.Trim(version, "^~>=<"),
					Language: language,
				})
			}
		}
	}

	return frameworks, nil
}

func detectPythonFrameworks(projectPath string) ([]Framework, error) {
	frameworks := []Framework{}
	patterns := FrameworkPatterns["Python"]

	files := []string{
		filepath.Join(projectPath, "requirements.txt"),
		filepath.Join(projectPath, "Pipfile"),
		filepath.Join(projectPath, "pyproject.toml"),
	}

	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			for pattern, fwName := range patterns {
				if strings.Contains(line, pattern) {
					version := extractVersion(line)
					frameworks = append(frameworks, Framework{
						Name:     fwName,
						Version:  version,
						Language: "Python",
					})
				}
			}
		}
	}

	return frameworks, nil
}

func detectGoFrameworks(projectPath string) ([]Framework, error) {
	goModPath := filepath.Join(projectPath, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return []Framework{}, nil
	}
	defer file.Close()

	frameworks := []Framework{}
	patterns := FrameworkPatterns["Go"]

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for pattern, fwName := range patterns {
			if strings.Contains(line, pattern) {
				version := extractVersion(line)
				frameworks = append(frameworks, Framework{
					Name:     fwName,
					Version:  version,
					Language: "Go",
				})
			}
		}
	}

	return frameworks, nil
}

func detectJavaFrameworks(projectPath string) ([]Framework, error) {
	frameworks := []Framework{}
	patterns := FrameworkPatterns["Java"]

	files := []string{
		filepath.Join(projectPath, "pom.xml"),
		filepath.Join(projectPath, "build.gradle"),
	}

	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			for pattern, fwName := range patterns {
				if strings.Contains(line, pattern) {
					frameworks = append(frameworks, Framework{
						Name:     fwName,
						Language: "Java",
					})
				}
			}
		}
	}

	return frameworks, nil
}

func detectSolidityFrameworks(projectPath string) ([]Framework, error) {
	frameworks := []Framework{}
	patterns := FrameworkPatterns["Solidity"]

	packageJSONPath := filepath.Join(projectPath, "package.json")
	file, err := os.Open(packageJSONPath)
	if err != nil {
		return frameworks, nil
	}
	defer file.Close()

	var packageJSON map[string]interface{}
	if err := json.NewDecoder(file).Decode(&packageJSON); err != nil {
		return frameworks, nil
	}

	deps := make(map[string]string)
	if dependencies, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
		for name, version := range dependencies {
			if v, ok := version.(string); ok {
				deps[name] = v
			}
		}
	}
	if devDependencies, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
		for name, version := range devDependencies {
			if v, ok := version.(string); ok {
				deps[name] = v
			}
		}
	}

	for depName, version := range deps {
		for pattern, fwName := range patterns {
			if strings.Contains(depName, pattern) {
				frameworks = append(frameworks, Framework{
					Name:     fwName,
					Version:  strings.Trim(version, "^~>=<"),
					Language: "Solidity",
				})
			}
		}
	}

	return frameworks, nil
}

func extractVersion(line string) string {
	parts := strings.Fields(line)
	for i, part := range parts {
		if strings.HasPrefix(part, "v") || strings.Contains(part, ".") {
			if i > 0 && (parts[i-1] == "==" || parts[i-1] == ">=") {
				return strings.Trim(part, "\"'")
			}
			return strings.Trim(part, "\"'v")
		}
	}
	return ""
}
