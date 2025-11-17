package utils

import "strings"

func FormatLanguages(languages []interface{}) []string {
	result := []string{}
	for _, lang := range languages {
		if langMap, ok := lang.(map[string]interface{}); ok {
			if name, ok := langMap["name"].(string); ok {
				result = append(result, name)
			}
		}
	}
	return result
}

func FormatFrameworks(frameworks []interface{}) []string {
	result := []string{}
	for _, fw := range frameworks {
		if fwMap, ok := fw.(map[string]interface{}); ok {
			if name, ok := fwMap["name"].(string); ok {
				result = append(result, name)
			}
		}
	}
	return result
}

func HasWebFramework(frameworks []string) bool {
	webFrameworks := map[string]bool{
		"React":       true,
		"Vue":         true,
		"Angular":     true,
		"Express":     true,
		"Next.js":     true,
		"Gin":         true,
		"Django":      true,
		"Flask":       true,
		"FastAPI":     true,
		"Spring Boot": true,
	}

	for _, fw := range frameworks {
		if webFrameworks[fw] {
			return true
		}
	}
	return false
}

func HasSolidityCode(languages []string) bool {
	for _, lang := range languages {
		if lang == "Solidity" {
			return true
		}
	}
	return false
}

func IsCryptoProject(frameworks []string) bool {
	cryptoFrameworks := map[string]bool{
		"Hardhat": true,
		"Truffle": true,
		"Foundry": true,
	}

	for _, fw := range frameworks {
		if cryptoFrameworks[fw] {
			return true
		}
	}
	return false
}

func IsProductionProject(hasTests bool, isGitRepo bool) bool {
	return hasTests && isGitRepo
}

func IsCriticalProject(domain string, hasWebFramework bool) bool {
	criticalDomains := map[string]bool{
		"finance":    true,
		"healthcare": true,
		"crypto":     true,
	}

	return criticalDomains[domain] || hasWebFramework
}

func ContainsAny(str string, substrings []string) bool {
	lowerStr := strings.ToLower(str)
	for _, substr := range substrings {
		if strings.Contains(lowerStr, substr) {
			return true
		}
	}
	return false
}
