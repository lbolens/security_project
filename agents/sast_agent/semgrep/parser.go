package semgrep

import (
	"strings"
)

func ExtractVulnType(checkID string) string {
	checkIDLower := strings.ToLower(checkID)

	if strings.Contains(checkIDLower, "sql-injection") || strings.Contains(checkIDLower, "sqli") {
		return "sql-injection"
	}
	if strings.Contains(checkIDLower, "xss") || strings.Contains(checkIDLower, "cross-site-scripting") {
		return "xss"
	}
	if strings.Contains(checkIDLower, "command-injection") || strings.Contains(checkIDLower, "os-command") {
		return "command-injection"
	}
	if strings.Contains(checkIDLower, "path-traversal") || strings.Contains(checkIDLower, "directory-traversal") {
		return "path-traversal"
	}
	if strings.Contains(checkIDLower, "crypto") || strings.Contains(checkIDLower, "weak-cipher") {
		return "weak-crypto"
	}
	if strings.Contains(checkIDLower, "hardcoded") || strings.Contains(checkIDLower, "secret") {
		return "hardcoded-secrets"
	}
	if strings.Contains(checkIDLower, "deserializ") {
		return "deserialization"
	}
	if strings.Contains(checkIDLower, "reentrancy") {
		return "reentrancy"
	}
	if strings.Contains(checkIDLower, "overflow") || strings.Contains(checkIDLower, "underflow") {
		return "integer-overflow"
	}
	if strings.Contains(checkIDLower, "delegatecall") {
		return "delegatecall"
	}
	if strings.Contains(checkIDLower, "tx.origin") || strings.Contains(checkIDLower, "tx-origin") {
		return "tx-origin"
	}
	if strings.Contains(checkIDLower, "xxe") {
		return "xxe"
	}
	if strings.Contains(checkIDLower, "jwt") {
		return "jwt-vulnerabilities"
	}
	if strings.Contains(checkIDLower, "eval") {
		return "eval-usage"
	}
	if strings.Contains(checkIDLower, "prototype") {
		return "prototype-pollution"
	}

	return "code-vulnerability"
}

func MapSemgrepSeverity(semgrepSev string, metadata Metadata) string {
	if metadata.Impact == "HIGH" && metadata.Likelihood == "HIGH" {
		return "critical"
	}

	switch semgrepSev {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	case "INFO":
		return "low"
	default:
		return "medium"
	}
}

func MapConfidence(semgrepConf string) string {
	confLower := strings.ToLower(semgrepConf)
	switch confLower {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func ExtractTitle(message string) string {
	if len(message) > 100 {
		return message[:97] + "..."
	}
	return message
}
