package gitleaks

import "strings"

func DetermineSecretType(ruleID string, tags []string) string {
	typeMap := map[string]string{
		"aws-access-token":        "aws-access-key",
		"aws-secret-key":          "aws-secret-key",
		"github-pat":              "github-token",
		"github-token":            "github-token",
		"gitlab-token":            "gitlab-token",
		"slack-access-token":      "slack-token",
		"slack-webhook":           "slack-webhook",
		"stripe-access-token":     "stripe-key",
		"paypal-braintree":        "paypal-secret",
		"gcp-api-key":             "gcp-api-key",
		"azure-client-secret":     "azure-client-secret",
		"private-key":             "private-key",
		"rsa-private-key":         "private-key",
		"jwt":                     "jwt-token",
		"generic-api-key":         "api-key",
		"mongodb-connection":      "mongodb-uri",
		"postgres-connection":     "postgres-password",
		"redis-password":          "redis-password",
		"ethereum-private-key":    "ethereum-private-key",
		"bitcoin-private-key":     "bitcoin-private-key",
		"mnemonic":                "mnemonic-phrase",
		"oauth-token":             "oauth-token",
		"twilio-api-key":          "twilio-api-key",
		"sendgrid-api-key":        "sendgrid-api-key",
		"mailgun-api-key":         "mailgun-api-key",
		"discord-webhook":         "discord-webhook",
	}

	ruleIDLower := strings.ToLower(ruleID)
	if secretType, ok := typeMap[ruleIDLower]; ok {
		return secretType
	}

	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		if strings.Contains(tagLower, "key") {
			return "api-key"
		}
		if strings.Contains(tagLower, "token") {
			return "oauth-token"
		}
		if strings.Contains(tagLower, "password") {
			return "credential"
		}
	}

	return "credential"
}

func RedactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}

	return secret[:4] + "***" + secret[len(secret)-4:]
}

func CalculateSeverity(secretType string, isProduction bool) string {
	criticalTypes := map[string]bool{
		"aws-access-key":      true,
		"aws-secret-key":      true,
		"private-key":         true,
		"ethereum-private-key": true,
		"bitcoin-private-key": true,
		"mnemonic-phrase":     true,
		"stripe-key":          true,
		"paypal-secret":       true,
		"gcp-api-key":         true,
		"azure-client-secret": true,
	}

	if criticalTypes[secretType] {
		return "critical"
	}

	if isProduction {
		return "high"
	}

	return "medium"
}
