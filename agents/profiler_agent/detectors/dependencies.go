package detectors

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Dependency struct {
	Name     string
	Version  string
	Language string
	IsDevDep bool
	FilePath string
}

func ExtractDependencies(projectPath string, languages []Language, includeDevDeps bool) ([]Dependency, error) {
	dependencies := []Dependency{}

	for _, lang := range languages {
		deps, err := extractForLanguage(projectPath, lang.Name, includeDevDeps)
		if err != nil {
			continue
		}
		dependencies = append(dependencies, deps...)
	}

	return dependencies, nil
}

func ExtractDependenciesForLanguage(projectPath string, language string, includeDevDeps bool) ([]Dependency, string, error) {
	deps, err := extractForLanguage(projectPath, language, includeDevDeps)
	if err != nil {
		return []Dependency{}, "", err
	}

	sourceFile := ""
	switch language {
	case "Go":
		sourceFile = filepath.Join(projectPath, "go.mod")
	case "JavaScript", "TypeScript":
		sourceFile = filepath.Join(projectPath, "package.json")
	case "Python":
		sourceFile = filepath.Join(projectPath, "requirements.txt")
	case "Rust":
		sourceFile = filepath.Join(projectPath, "Cargo.toml")
	case "Java":
		sourceFile = filepath.Join(projectPath, "pom.xml")
	case "Ruby":
		sourceFile = filepath.Join(projectPath, "Gemfile")
	case "PHP":
		sourceFile = filepath.Join(projectPath, "composer.json")
	}

	return deps, sourceFile, nil
}

func extractForLanguage(projectPath string, language string, includeDevDeps bool) ([]Dependency, error) {
	switch language {
	case "Go":
		return parseGoMod(projectPath, includeDevDeps)
	case "JavaScript", "TypeScript":
		return parsePackageJSON(projectPath, language, includeDevDeps)
	case "Python":
		return parseRequirementsTxt(projectPath, includeDevDeps)
	case "Rust":
		return parseCargoToml(projectPath, includeDevDeps)
	case "Java":
		return parsePomXML(projectPath, includeDevDeps)
	case "Ruby":
		return parseGemfile(projectPath, includeDevDeps)
	case "PHP":
		return parseComposerJSON(projectPath, includeDevDeps)
	default:
		return []Dependency{}, nil
	}
}

func parseGoMod(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	goModPath := filepath.Join(projectPath, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	dependencies := []Dependency{}
	scanner := bufio.NewScanner(file)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		if strings.HasPrefix(line, "require ") || inRequireBlock {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				if name == "require" && len(parts) >= 3 {
					name = parts[1]
					parts = parts[1:]
				}
				version := parts[1]

				dependencies = append(dependencies, Dependency{
					Name:     name,
					Version:  version,
					Language: "Go",
					IsDevDep: false,
					FilePath: goModPath,
				})
			}
		}
	}

	return dependencies, nil
}

func parsePackageJSON(projectPath string, language string, includeDevDeps bool) ([]Dependency, error) {
	packageJSONPath := filepath.Join(projectPath, "package.json")
	file, err := os.Open(packageJSONPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	var packageJSON map[string]interface{}
	if err := json.NewDecoder(file).Decode(&packageJSON); err != nil {
		return []Dependency{}, nil
	}

	dependencies := []Dependency{}

	if deps, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			if v, ok := version.(string); ok {
				dependencies = append(dependencies, Dependency{
					Name:     name,
					Version:  v,
					Language: language,
					IsDevDep: false,
					FilePath: packageJSONPath,
				})
			}
		}
	}

	if includeDevDeps {
		if devDeps, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
			for name, version := range devDeps {
				if v, ok := version.(string); ok {
					dependencies = append(dependencies, Dependency{
						Name:     name,
						Version:  v,
						Language: language,
						IsDevDep: true,
						FilePath: packageJSONPath,
					})
				}
			}
		}
	}

	return dependencies, nil
}

func parseRequirementsTxt(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	requirementsPath := filepath.Join(projectPath, "requirements.txt")
	file, err := os.Open(requirementsPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	dependencies := []Dependency{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, version := parsePythonRequirement(line)
		if name != "" {
			dependencies = append(dependencies, Dependency{
				Name:     name,
				Version:  version,
				Language: "Python",
				IsDevDep: false,
				FilePath: requirementsPath,
			})
		}
	}

	return dependencies, nil
}

func parsePythonRequirement(line string) (string, string) {
	for _, sep := range []string{"==", ">=", "<=", "~=", ">", "<"} {
		if strings.Contains(line, sep) {
			parts := strings.Split(line, sep)
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	return strings.TrimSpace(line), ""
}

func parseCargoToml(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	cargoPath := filepath.Join(projectPath, "Cargo.toml")
	file, err := os.Open(cargoPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	dependencies := []Dependency{}
	scanner := bufio.NewScanner(file)
	inDepsSection := false
	inDevDepsSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[dependencies]" {
			inDepsSection = true
			inDevDepsSection = false
			continue
		}

		if line == "[dev-dependencies]" {
			inDepsSection = false
			inDevDepsSection = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inDepsSection = false
			inDevDepsSection = false
			continue
		}

		if (inDepsSection || (inDevDepsSection && includeDevDeps)) && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"")

				dependencies = append(dependencies, Dependency{
					Name:     name,
					Version:  version,
					Language: "Rust",
					IsDevDep: inDevDepsSection,
					FilePath: cargoPath,
				})
			}
		}
	}

	return dependencies, nil
}

func parsePomXML(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	pomPath := filepath.Join(projectPath, "pom.xml")
	file, err := os.Open(pomPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	dependencies := []Dependency{}
	scanner := bufio.NewScanner(file)
	inDependency := false
	currentName := ""
	currentVersion := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<dependency>") {
			inDependency = true
			currentName = ""
			currentVersion = ""
			continue
		}

		if strings.Contains(line, "</dependency>") {
			if currentName != "" {
				dependencies = append(dependencies, Dependency{
					Name:     currentName,
					Version:  currentVersion,
					Language: "Java",
					IsDevDep: false,
					FilePath: pomPath,
				})
			}
			inDependency = false
			continue
		}

		if inDependency {
			if strings.Contains(line, "<artifactId>") {
				currentName = extractXMLValue(line, "artifactId")
			}
			if strings.Contains(line, "<version>") {
				currentVersion = extractXMLValue(line, "version")
			}
		}
	}

	return dependencies, nil
}

func parseGemfile(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	gemfilePath := filepath.Join(projectPath, "Gemfile")
	file, err := os.Open(gemfilePath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	dependencies := []Dependency{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "gem ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.Trim(parts[1], "\"'")
				version := ""
				if len(parts) >= 3 {
					version = strings.Trim(parts[2], "\"',")
				}
				dependencies = append(dependencies, Dependency{
					Name:     name,
					Version:  version,
					Language: "Ruby",
					IsDevDep: false,
					FilePath: gemfilePath,
				})
			}
		}
	}

	return dependencies, nil
}

func parseComposerJSON(projectPath string, includeDevDeps bool) ([]Dependency, error) {
	composerPath := filepath.Join(projectPath, "composer.json")
	file, err := os.Open(composerPath)
	if err != nil {
		return []Dependency{}, nil
	}
	defer file.Close()

	var composerJSON map[string]interface{}
	if err := json.NewDecoder(file).Decode(&composerJSON); err != nil {
		return []Dependency{}, nil
	}

	dependencies := []Dependency{}

	if deps, ok := composerJSON["require"].(map[string]interface{}); ok {
		for name, version := range deps {
			if v, ok := version.(string); ok {
				dependencies = append(dependencies, Dependency{
					Name:     name,
					Version:  v,
					Language: "PHP",
					IsDevDep: false,
					FilePath: composerPath,
				})
			}
		}
	}

	if includeDevDeps {
		if devDeps, ok := composerJSON["require-dev"].(map[string]interface{}); ok {
			for name, version := range devDeps {
				if v, ok := version.(string); ok {
					dependencies = append(dependencies, Dependency{
						Name:     name,
						Version:  v,
						Language: "PHP",
						IsDevDep: true,
						FilePath: composerPath,
					})
				}
			}
		}
	}

	return dependencies, nil
}

func extractXMLValue(line string, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(line, openTag)
	end := strings.Index(line, closeTag)
	if start >= 0 && end > start {
		return line[start+len(openTag) : end]
	}
	return ""
}
