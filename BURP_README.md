JSSniper - JavaScript Security Scanner for Burp Suite

Overview

JSSniper is a comprehensive JavaScript security scanner extension for Burp Suite that automatically detects and reports security vulnerabilities, exposed secrets, hardcoded credentials, suspicious code patterns, and potential security issues in JavaScript files.

The extension performs deep analysis of all JavaScript content within scope, identifying critical security risks including API keys, database credentials, exposed endpoints, debug information, and vulnerable coding patterns.

Key Features

Security Detection

Detects 12+ types of API keys and secrets (AWS, GitHub, Stripe, Twilio, Slack, Google, Firebase, JWT, and more)
Identifies hardcoded database credentials and connection strings
Finds exposed authentication tokens and bearer tokens
Detects private keys and sensitive cryptographic material
Identifies Base64-encoded sensitive content

Endpoint Discovery

Maps API routes and endpoints throughout the application
Discovers admin panels, debug endpoints, and internal paths
Identifies WebSocket endpoints and real-time communication channels
Finds backup files and potentially exposable resources
Discovers API versioning patterns and hidden endpoints

Code Quality Analysis

Detects minified code that may hide vulnerabilities
Identifies source map references for source code exposure
Analyzes dependency usage and import patterns
Finds commented code that may contain sensitive information
Detects debug mode enabled in production

Framework and Library Detection

Identifies JavaScript frameworks and libraries in use
Detects outdated and vulnerable library versions
Identifies deprecated patterns and unsafe DOM operations
Finds use of eval() and similar dangerous functions
Detects XMLHttpRequest patterns and AJAX usage

Professional Implementation

Thread-Safe Architecture: All scanning operations run in background threads to maintain Burp Suite responsiveness
Efficient Resource Management: Properly handles large projects and extensive JavaScript files
Clean Unloading: Properly releases all resources when extension is unloaded
Secure Operations: Treats all HTTP content as untrusted, preventing injection vulnerabilities
Burp Integration: Uses Burp's native HTTP processing and session handling

Installation

Prerequisites

Burp Suite Professional/Community Edition 2024.8 or later
Java 11 or higher

Installation Steps

Download the JSSniper JAR file from releases
In Burp Suite, navigate to Extensions
Click Add
Select JAR file: jssniper-2.0.0.jar
The extension loads automatically
A new JSSniper tab appears in the main window

Usage

Basic Scanning

1. Open the JSSniper tab in Burp Suite
2. Click "Scan All JavaScript"
3. The extension scans all JavaScript in your project scope
4. Results display in severity order

Interpreting Results

CRITICAL - Secrets and Keys: API keys, authentication tokens, database credentials
HIGH - Endpoints and Paths: API routes, admin panels, internal endpoints
MEDIUM - Hardcoded Values and Suspicious Code: IPs, domains, debug statements
INFO - Frameworks and Code Quality: Library detection and code structure analysis

Security Testing Workflow

1. Add target application to Burp Suite scope
2. Browse application normally to collect JavaScript
3. Open JSSniper tab
4. Run automated scan
5. Review findings by severity
6. Verify each finding manually
7. Generate report for stakeholders

Technical Specifications

Detection Patterns

The extension uses 50+ carefully crafted regular expressions organized into categories:

Secret Patterns (12+ types)
- API Keys and Service Credentials
- Authentication Tokens and Credentials
- Database Connection Strings
- Private Keys and Certificates

Endpoint Patterns (8 types)
- API Routes and Endpoints
- Admin and Internal Paths
- WebSocket Endpoints
- Backup Files

Hardcoded Value Patterns (6 types)
- IP Addresses (Public and Internal)
- Hostnames and Domains
- Email Addresses and Usernames
- Port Numbers

Framework Patterns (9 types)
- JavaScript Libraries and Frameworks
- Unsafe Operations
- Deprecated Patterns
- Dangerous Functions

Suspicious Code Patterns (7 types)
- Console Logging
- Debug Mode Indicators
- TODO/FIXME Comments
- Obfuscation Functions

Performance

Single JavaScript File: Typically <100ms
Full Project Scan: Depends on JavaScript volume, usually <30 seconds
Large Projects: Efficiently handles projects with 1000+ JavaScript files
Memory Usage: Optimized for long-term scanning sessions

Architecture

Thread Management

Scanning Operations: Dedicated thread pool (4 concurrent threads)
UI Responsiveness: All blocking operations run asynchronously
Clean Shutdown: Proper thread termination on extension unload

Resource Management

No Long-Term References: Doesn't maintain references to HTTP messages
Temporary Storage: Uses Burp's temporary file context for large data
Memory Efficient: Processes content without buffering entire projects

Security Considerations

Input Validation

All HTTP content treated as untrusted
Regular expressions validated for injection safety
No command execution from external sources

Data Handling

All findings stored in memory only
No external communication or data transmission
Results never cached to disk
Complies with offline working requirement

Network Operations

Uses Burp's HTTP processing infrastructure
Respects proxy settings and session handling
No direct network calls bypass Burp's control

Troubleshooting

Extension Fails to Load

Check Burp Suite version (requires 2024.8 or later)
Verify Java 11+ is installed
Check error log: Extender tab > Extension Details > Errors

No Findings Detected

Ensure JavaScript files are in scope
Verify responses contain JavaScript content
Check Content-Type headers are correct
Run manual scan: JSSniper tab > Scan All JavaScript

Slow Scanning

Large number of JavaScript files may take time
Reduce scope to specific application sections
Check system memory availability
Monitor CPU usage during scan

Missing Detections

Not all patterns may match every codebase
Some obfuscated code may not be detected
Consider reporting new patterns via GitHub

Configuration

Extension Settings

Auto-Scan: Enabled by default for all in-scope JavaScript
Passive Scanning: Analyzes responses without sending new requests
Thread Pool Size: 4 concurrent scanner threads
Result Caching: Prevents duplicate findings in same session

Scope Management

Only JavaScript in Burp Suite scope is analyzed
Respects target and URL scope configuration
Can be used with custom scope rules
Integrates with Burp's session handling

Advanced Usage

Integration with Burp Workflows

Monitor for Secrets

1. Configure JSSniper to auto-scan
2. Enable high-severity finding alerts
3. Review critical findings before production deployment
4. Use results to implement secret rotation policies

Continuous Security Monitoring

1. Run regular scans during development
2. Integrate with CI/CD pipelines using Burp CLI
3. Track findings over time
4. Maintain vulnerability baseline

Compliance and Standards

Supports security compliance requirements:
- OWASP Top 10 (Injection, Sensitive Data Exposure, Using Components with Known Vulnerabilities)
- CWE Coverage (CWE-798, CWE-327, CWE-434, CWE-502, CWE-213)
- SANS Top 25 Software Errors

Limitations and Known Issues

Limitations

Minified code analysis limited by obfuscation
Some dynamically-generated endpoints may not be detected
Encrypted content cannot be analyzed
Comment removal patterns may miss some sensitive information

Handling Large Projects

For projects with 10000+ JavaScript files:
- Use scope filtering to limit analysis
- Run scans during non-peak hours
- Monitor memory usage
- Consider multiple scan sessions

Building from Source

Prerequisites

Java Development Kit 11 or higher
Gradle 7.0 or higher
Git

Build Steps

git clone https://github.com/PortSwigger/jssniper-burp.git
cd jssniper-burp
gradle build

Output

Build output: build/libs/jssniper-2.0.0.jar
All dependencies included in JAR
No additional installation required

Contributing

Reporting Issues

Use GitHub Issues with clear description
Include reproduction steps
Provide sample JavaScript if possible
Specify Burp Suite version used

Submitting Improvements

Fork repository
Create feature branch
Add tests for new functionality
Submit pull request with clear description
Follow existing code style and patterns

Development Guidelines

Code Standards

Java 11+ syntax
Thread-safe implementations
Comprehensive error handling
Unit test coverage for new features

Testing Requirements

Existing tests must pass
New features require unit tests
Manual testing on Burp Suite required
Documentation updated for new features

License

This extension is provided as-is for authorized security testing only.
Unauthorized testing of systems you do not own or have permission to test is illegal.

Support and Feedback

Official Website: https://github.com/PortSwigger/jssniper-burp
Documentation: See built-in help and README
Issue Reporting: GitHub Issues
Feature Requests: GitHub Discussions

Professional Disclaimer

This extension is designed for authorized security testing and vulnerability assessment purposes only.

Users are responsible for:
- Obtaining proper authorization before testing any systems
- Complying with all applicable laws and regulations
- Using findings responsibly and ethically
- Protecting sensitive information discovered during testing

Unauthorized testing is illegal and unethical.

Version History

Version 2.0.0 (Current)
- Professional Burp Suite extension implementation
- 50+ detection patterns
- Thread-safe architecture
- Burp Montoya API integration
- Complete security analysis

Version 1.0
- Original command-line tool
- Basic JavaScript analysis

Acknowledgments

Built for the PortSwigger Burp Suite community
Inspired by industry best practices for security scanning
Developed following OWASP guidelines for secure coding
