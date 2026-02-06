# Security Policy

## Supported Versions

We release patches for security vulnerabilities. The following table shows which versions are currently supported:

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them to the OpenWallet Foundation security team:

1. **Email**: <security@openwallet.foundation>
2. **Subject**: `[SECURITY] identity-common-ts: <brief description>`

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, injection, etc.)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Response Timeline

- We will acknowledge receipt of your vulnerability report within **3 business days**
- We will provide a more detailed response within **10 business days**
- We will work to fix the vulnerability as quickly as possible

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find any similar problems
3. Prepare fixes for all supported versions
4. Release patches as soon as possible

## Security Best Practices

When using this library, please follow these security best practices:

1. **Keep dependencies up to date**: Regularly update to the latest version
2. **Validate inputs**: Always validate inputs before passing them to library functions
3. **Use secure cryptographic implementations**: When providing crypto callbacks, use well-tested implementations
4. **Follow the principle of least privilege**: Only request the permissions your application needs

## Security-Related Configuration

This library is designed to be platform-agnostic and requires users to provide cryptographic implementations. When doing so:

- Use secure random number generators
- Use approved cryptographic algorithms and key sizes
- Properly manage and protect cryptographic keys
- Follow industry standards for JWT/CWT validation
