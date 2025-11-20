package analyzer

import "fmt"

type RemediationInput struct {
	SecretType   string
	FilePath     string
	CommitHash   string
	IsInGit      bool
}

func (c *OllamaClient) GenerateRemediation(finding RemediationInput, projectContext ProjectContextInput) (string, error) {
	prompt := buildRemediationPrompt(finding, projectContext)

	response, err := c.generate(prompt)
	if err != nil {
		return generateGenericRemediation(finding.SecretType, finding.IsInGit), nil
	}

	if response == "" {
		return generateGenericRemediation(finding.SecretType, finding.IsInGit), nil
	}

	return response, nil
}

func buildRemediationPrompt(finding RemediationInput, projectContext ProjectContextInput) string {
	return fmt.Sprintf(`Generate a detailed remediation plan for this exposed secret.

Secret Type: %s
File: %s
Exposed in Git: %v
Commit Hash: %s
Project Type: %s

Provide:
1. **Immediate Actions** (revoke, rotate)
   - Specific steps to revoke this exact secret type
   - How to rotate/generate new secret
2. **Code Fix** (remove from code, use environment variables)
   - Where to store secrets properly (env vars, vault, secrets manager)
   - Code changes needed
3. **Git History** (if exposed in commits)
   - How to remove from git history (git filter-repo, BFG)
   - Warning about public repos
4. **Prevention** (pre-commit hooks, secret scanning CI/CD)
   - Tools to prevent future leaks

Keep it actionable and specific to %s secrets.
Format in markdown with clear sections.`,
		finding.SecretType,
		finding.FilePath,
		finding.IsInGit,
		finding.CommitHash,
		projectContext.Type,
		finding.SecretType,
	)
}

func generateGenericRemediation(secretType string, isInGit bool) string {
	remediations := map[string]string{
		"aws-access-key": `**Immediate Actions**:
1. Revoke key in AWS IAM Console immediately
2. Check CloudTrail for unauthorized usage
3. Generate new access key with principle of least privilege

**Code Fix**:
` + "```" + `bash
# Store in environment variable
export AWS_ACCESS_KEY_ID=your_new_key
` + "```" + `

**Prevention**:
- Add .env to .gitignore
- Use pre-commit hook with gitleaks
- Enable AWS Secrets Manager`,

		"github-token": `**Immediate Actions**:
1. Revoke token at github.com/settings/tokens
2. Check audit log for unauthorized usage
3. Generate new token with minimal scopes

**Code Fix**:
` + "```" + `bash
# Store in environment variable
export GITHUB_TOKEN=your_new_token
` + "```" + `

**Prevention**:
- Use GitHub Actions secrets for CI/CD
- Never commit tokens to code`,

		"private-key": `**Immediate Actions**:
1. Revoke/invalidate the private key immediately
2. Generate new key pair
3. Never commit private keys

**Code Fix**:
` + "```" + `bash
# Store private keys outside repo
mv private_key.pem ~/.ssh/
chmod 600 ~/.ssh/private_key.pem
` + "```" + `

**Prevention**:
- Use key management services (AWS KMS, HashiCorp Vault)
- Add *.pem to .gitignore`,

		"api-key": `**Immediate Actions**:
1. Revoke the API key in the service dashboard
2. Generate new API key
3. Store in .env file (gitignored)

**Code Fix**:
` + "```" + `bash
# Use environment variables
export API_KEY=your_new_key
` + "```" + `

**Prevention**:
- Add .env to .gitignore
- Use secret management tools`,

		"stripe-key": `**Immediate Actions**:
1. Revoke key in Stripe Dashboard → Developers → API keys
2. Check Stripe logs for suspicious transactions
3. Generate new restricted API key

**Code Fix**:
` + "```" + `bash
export STRIPE_SECRET_KEY=sk_live_new_key
` + "```" + `

**Prevention**:
- Use environment variables
- Never commit production keys`,

		"jwt-token": `**Immediate Actions**:
1. Invalidate the JWT token
2. Rotate signing secret
3. Force re-authentication of users

**Code Fix**:
` + "```" + `bash
export JWT_SECRET=new_secret
` + "```" + `

**Prevention**:
- Use short-lived tokens
- Store signing secret in vault`,
	}

	baseRemediation := remediations[secretType]
	if baseRemediation == "" {
		baseRemediation = `**Immediate Actions**:
1. Revoke the exposed secret immediately
2. Rotate/generate new credentials
3. Store secrets in environment variables or secret management system

**Prevention**:
- Add .env to .gitignore
- Use pre-commit hooks
- Enable secret scanning in CI/CD`
	}

	if isInGit {
		baseRemediation += `

**Git History Cleanup**:
` + "```" + `bash
# Remove from git history
git filter-repo --path <file> --invert-paths
# Or use BFG Repo-Cleaner
bfg --delete-files <file>

# Force push (if private repo)
git push --force
` + "```" + `

**Warning**: If this is a public repository, consider the secret permanently compromised.`
	}

	return baseRemediation
}
