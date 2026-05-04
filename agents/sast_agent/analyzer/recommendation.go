package analyzer

import (
	"fmt"
)

type RecommendationInput struct {
	Type        string
	FilePath    string
	LineNumber  int
	CodeSnippet string
	CWE         string
	OWASP       string
}

func (c *OllamaClient) GenerateRecommendation(finding RecommendationInput) (string, error) {
	prompt := buildRecommendationPrompt(finding)

	response, err := c.generate(prompt)
	if err != nil {
		return generateGenericRecommendation(finding.Type), nil
	}

	if response == "" {
		return generateGenericRecommendation(finding.Type), nil
	}

	return response, nil
}

func buildRecommendationPrompt(finding RecommendationInput) string {
	return fmt.Sprintf(`Generate a practical fix recommendation for this security vulnerability.

Vulnerability: %s
File: %s
Line: %d
Code:
%s

CWE: %s
OWASP: %s

Provide:
1. **Root cause**: Why is this vulnerable?
2. **Fix**: Exact code changes needed (with code examples)
3. **Alternative solutions**: Other ways to mitigate
4. **Testing**: How to verify the fix works

Keep it concise and actionable. Use markdown format with code blocks.`,
		finding.Type,
		finding.FilePath,
		finding.LineNumber,
		finding.CodeSnippet,
		finding.CWE,
		finding.OWASP,
	)
}

func generateGenericRecommendation(vulnType string) string {
	recommendations := map[string]string{
		"sql-injection": `**Root cause**: User input concatenated directly into SQL query without sanitization.

**Fix**: Use parameterized queries or prepared statements:
` + "```" + `go
// Bad
db.Query("SELECT * FROM users WHERE id = " + userID)

// Good
db.Query("SELECT * FROM users WHERE id = ?", userID)
` + "```" + `

**Alternative**: Use an ORM like GORM with safe query builders.

**Testing**: Try SQL injection payloads like '1 OR 1=1' to verify the fix prevents injection.`,

		"xss": `**Root cause**: User input rendered in HTML without proper escaping.

**Fix**: Sanitize and escape all user input before rendering:
` + "```" + `javascript
// Bad
element.innerHTML = userInput;

// Good
element.textContent = userInput;
// Or use DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);
` + "```" + `

**Alternative**: Use a templating engine with auto-escaping (React, Vue, Angular).

**Testing**: Try XSS payloads like '<script>alert(1)</script>' to verify escaping works.`,

		"command-injection": `**Root cause**: User input passed directly to shell command execution.

**Fix**: Avoid shell execution and use language APIs:
` + "```" + `python
# Bad
os.system("ping " + user_input)

# Good
subprocess.run(["ping", user_input], check=True)
` + "```" + `

**Alternative**: Use input validation with allowlists.

**Testing**: Try command injection payloads like '; ls' to verify sanitization.`,

		"path-traversal": `**Root cause**: User-controlled file paths allow directory traversal.

**Fix**: Validate and sanitize file paths:
` + "```" + `go
// Bad
filepath.Join(baseDir, userPath)

// Good
cleanPath := filepath.Clean(userPath)
if strings.Contains(cleanPath, "..") {
    return errors.New("invalid path")
}
fullPath := filepath.Join(baseDir, cleanPath)
` + "```" + `

**Alternative**: Use allowlists for permitted file names.

**Testing**: Try path traversal payloads like '../../../etc/passwd' to verify prevention.`,

		"weak-crypto": `**Root cause**: Using weak or deprecated cryptographic algorithms.

**Fix**: Use strong, modern cryptographic algorithms:
` + "```" + `go
// Bad
md5.Sum(data)

// Good
sha256.Sum256(data)
` + "```" + `

**Alternative**: Use bcrypt for password hashing, AES-256 for encryption.

**Testing**: Review NIST and OWASP guidelines for approved algorithms.`,

		"hardcoded-secrets": `**Root cause**: Secrets hardcoded in source code.

**Fix**: Use environment variables or secret management:
` + "```" + `go
// Bad
apiKey := os.Getenv("API_KEY")

// Good
apiKey := os.Getenv("API_KEY")
` + "```" + `

**Alternative**: Use secret management tools like HashiCorp Vault, AWS Secrets Manager.

**Testing**: Scan codebase for credentials and ensure all are externalized.`,

		"deserialization": `**Root cause**: Deserializing untrusted data can lead to code execution.

**Fix**: Validate data before deserialization:
` + "```" + `python
# Bad
pickle.loads(user_data)

# Good
json.loads(user_data)  # Use safe formats like JSON
` + "```" + `

**Alternative**: Use allowlists for permitted classes during deserialization.

**Testing**: Try malicious serialized payloads to verify prevention.`,

		"reentrancy": `**Root cause**: External calls before state updates allow reentrancy attacks.

**Fix**: Follow checks-effects-interactions pattern:
` + "```" + `solidity
// Bad
recipient.call{value: amount}("");
balances[msg.sender] -= amount;

// Good
balances[msg.sender] -= amount;
recipient.call{value: amount}("");
` + "```" + `

**Alternative**: Use ReentrancyGuard from OpenZeppelin.

**Testing**: Write unit tests simulating reentrancy attacks.`,

		"integer-overflow": `**Root cause**: Arithmetic operations can overflow/underflow.

**Fix**: Use SafeMath library or Solidity 0.8+:
` + "```" + `solidity
// Bad (Solidity < 0.8)
uint256 result = a + b;

// Good (Solidity 0.8+)
uint256 result = a + b;  // Built-in overflow checks

// Or use SafeMath
uint256 result = a.add(b);
` + "```" + `

**Alternative**: Add manual overflow checks.

**Testing**: Test edge cases with maximum values.`,
	}

	if rec, ok := recommendations[vulnType]; ok {
		return rec
	}

	return "Review and fix the security issue according to industry best practices for " + vulnType + "."
}
