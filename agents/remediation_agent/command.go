package main

import (
	"encoding/json"
	"fmt"
)

func GenerateDependencyFix(input DependencyFixInput) (*DependencyFixOutput, error) {
	finding := input.Finding

	packageName := GetStringValue(finding, "component_name")
	currentVersion := GetStringValue(finding, "current_version")
	targetVersion := GetStringValue(finding, "target_version")

	packageManager := DetectPackageManager(finding)

	updateCommand := generateUpdateCommand(packageManager, packageName, targetVersion)
	verifyCommand := generateVerifyCommand(packageManager, packageName)
	rollbackCommand := generateRollbackCommand(packageManager, packageName, currentVersion)

	return &DependencyFixOutput{
		Fix: DependencyFixDetails{
			UpdateCommand:   updateCommand,
			VerifyCommand:   verifyCommand,
			RollbackCommand: rollbackCommand,
		},
	}, nil
}

func GenerateDependencyFixFromFinding(finding map[string]interface{}) (Fix, error) {
	packageName := GetStringValue(finding, "component_name")
	currentVersion := GetStringValue(finding, "current_version")
	targetVersion := GetStringValue(finding, "target_version")
	cve := GetStringValue(finding, "cve")
	cvss := GetFloatValue(finding, "cvss")

	if targetVersion == "" {
		targetVersion = "latest"
	}

	packageManager := DetectPackageManager(finding)

	prompt := fmt.Sprintf(`Generate specific commands to fix this dependency vulnerability.

Vulnerability:
- Package: %s
- Current Version: %s
- Fixed Version: %s
- CVE: %s
- CVSS: %.1f

Package Manager: %s

Generate:
1. Exact command to update the dependency
2. Command to verify the update
3. Any additional steps needed (rebuild, restart, etc.)

Respond in JSON:
{
  "update_command": "exact command to run",
  "verify_command": "command to verify update worked",
  "additional_steps": ["step 1", "step 2"],
  "breaking_changes": "description of potential breaking changes or 'none expected'",
  "rollback_command": "command to rollback if needed"
}`,
		packageName,
		currentVersion,
		targetVersion,
		cve,
		cvss,
		packageManager,
	)

	response, err := callOllama(prompt)
	if err != nil {
		return generateFallbackDependencyFix(finding, packageManager), nil
	}

	var fixData struct {
		UpdateCommand   string   `json:"update_command"`
		VerifyCommand   string   `json:"verify_command"`
		AdditionalSteps []string `json:"additional_steps"`
		BreakingChanges string   `json:"breaking_changes"`
		RollbackCommand string   `json:"rollback_command"`
	}

	if err := json.Unmarshal([]byte(response), &fixData); err != nil {
		return generateFallbackDependencyFix(finding, packageManager), nil
	}

	updateCommand := fixData.UpdateCommand
	if updateCommand == "" {
		updateCommand = generateUpdateCommand(packageManager, packageName, targetVersion)
	}

	description := fmt.Sprintf("Update %s from %s to %s to fix %s", packageName, currentVersion, targetVersion, cve)
	impact := fixData.BreakingChanges
	if impact == "" {
		impact = "Dependency update may introduce minor API changes"
	}
	rationale := fmt.Sprintf("Resolves %s (CVSS %.1f) by upgrading to patched version", cve, cvss)

	return Fix{
		Type:           "dependency-update",
		Description:    description,
		Command:        updateCommand,
		PackageName:    packageName,
		CurrentVersion: currentVersion,
		TargetVersion:  targetVersion,
		Impact:         impact,
		Rationale:      rationale,
		BreakingChange: false,
	}, nil
}

func generateFallbackDependencyFix(finding map[string]interface{}, packageManager string) Fix {
	packageName := GetStringValue(finding, "component_name")
	currentVersion := GetStringValue(finding, "current_version")
	targetVersion := GetStringValue(finding, "target_version")
	cve := GetStringValue(finding, "cve")
	cvss := GetFloatValue(finding, "cvss")

	if targetVersion == "" {
		targetVersion = "latest"
	}

	updateCommand := generateUpdateCommand(packageManager, packageName, targetVersion)

	description := fmt.Sprintf("Update %s from %s to %s to fix %s", packageName, currentVersion, targetVersion, cve)
	impact := "Dependency update may introduce minor API changes"
	rationale := fmt.Sprintf("Resolves %s (CVSS %.1f) by upgrading to patched version", cve, cvss)

	return Fix{
		Type:           "dependency-update",
		Description:    description,
		Command:        updateCommand,
		PackageName:    packageName,
		CurrentVersion: currentVersion,
		TargetVersion:  targetVersion,
		Impact:         impact,
		Rationale:      rationale,
		BreakingChange: false,
	}
}

func generateUpdateCommand(packageManager, packageName, version string) string {
	switch packageManager {
	case "npm":
		return fmt.Sprintf("npm install %s@%s", packageName, version)
	case "yarn":
		return fmt.Sprintf("yarn add %s@%s", packageName, version)
	case "pip":
		return fmt.Sprintf("pip install %s==%s", packageName, version)
	case "go":
		return fmt.Sprintf("go get %s@%s", packageName, version)
	case "maven":
		return fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", packageName, version)
	case "gradle":
		return fmt.Sprintf("// Update %s to %s in build.gradle", packageName, version)
	default:
		return fmt.Sprintf("# Update %s to version %s", packageName, version)
	}
}

func generateVerifyCommand(packageManager, packageName string) string {
	switch packageManager {
	case "npm":
		return fmt.Sprintf("npm list %s", packageName)
	case "yarn":
		return fmt.Sprintf("yarn list --pattern %s", packageName)
	case "pip":
		return fmt.Sprintf("pip show %s", packageName)
	case "go":
		return fmt.Sprintf("go list -m %s", packageName)
	default:
		return fmt.Sprintf("# Verify %s installation", packageName)
	}
}

func generateRollbackCommand(packageManager, packageName, version string) string {
	if version == "" {
		return "# Restore from package lock file"
	}

	switch packageManager {
	case "npm":
		return fmt.Sprintf("npm install %s@%s", packageName, version)
	case "yarn":
		return fmt.Sprintf("yarn add %s@%s", packageName, version)
	case "pip":
		return fmt.Sprintf("pip install %s==%s", packageName, version)
	case "go":
		return fmt.Sprintf("go get %s@%s", packageName, version)
	default:
		return fmt.Sprintf("# Rollback %s to version %s", packageName, version)
	}
}

func GenerateSecretsRemediation(finding map[string]interface{}) (Fix, error) {
	filePath := GetStringValue(finding, "file_path")
	lineNumber := GetIntValue(finding, "line_number")

	codeBefore := `apiKey := "sk_live_redacted"`
	codeAfter := `apiKey := os.Getenv("API_KEY")`

	description := "Remove hardcoded secret and use environment variable"
	impact := "Requires setting environment variable before deployment"
	rationale := "Environment variables keep secrets out of source code and git history"

	return Fix{
		Type:           "configuration",
		Description:    description,
		CodeBefore:     codeBefore,
		CodeAfter:      codeAfter,
		FilePath:       filePath,
		LineNumber:     lineNumber,
		Impact:         impact,
		Rationale:      rationale,
		BreakingChange: false,
	}, nil
}
