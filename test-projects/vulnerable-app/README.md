# Vulnerable Test Application

This is a test application with intentional security vulnerabilities for testing the security pipeline.

## Known Vulnerabilities

### Code Vulnerabilities (SAST)
1. **SQL Injection** in `main.go:getUserHandler()` - Line 29
2. **SQL Injection** in `main.go:searchHandler()` - Line 42
3. **Hardcoded credentials** in `main.go` - Line 17

### Dependency Vulnerabilities (SCA)
1. **lodash 4.17.20** - CVE-2021-23337 (Command Injection)
2. **express 4.16.0** - Multiple CVEs
3. **axios 0.21.0** - CVE-2021-3749 (SSRF)
4. **flask 1.1.1** - CVE-2019-1010083
5. **Django 2.2.10** - Multiple CVEs
6. **Pillow 7.0.0** - Multiple CVEs

### Exposed Secrets
1. AWS Access Key ID in `.env`
2. AWS Secret Access Key in `.env`
3. Stripe Secret Key in `.env`
4. GitHub Personal Access Token in `.env`
5. Database credentials in `.env`

## Project Type
- **Type**: API/Web Service
- **Languages**: Go, JavaScript, Python
- **Frameworks**: Gin (Go), Express (Node.js), Flask/Django (Python)
- **Domain**: E-commerce/Finance
- **Criticality**: High
