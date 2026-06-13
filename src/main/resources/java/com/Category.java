package com.jssniper;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM;
import static burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.TENTATIVE;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW;
import static burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;

/**
 * Each finding category maps to a Burp issue type and carries the
 * Title / Description / Impact / Remediation text shown in the dashboard.
 * The {@code key} matches the first column of patterns.tsv (VULN_LIBS is
 * produced separately by {@link LibraryCheck}).
 */
public enum Category {

    API_KEYS("api_keys", "Exposed API Keys & Access Tokens", HIGH, FIRM, true,
            "JavaScript served to the browser contains strings matching the format of API keys, "
                    + "access tokens or service credentials (AWS, Google, Stripe, GitHub, Slack, JWTs and similar).",
            "Anyone who can read the script can reuse these credentials to call the associated service, "
                    + "potentially accessing data, incurring cost, or pivoting into back-end systems. Client-side "
                    + "keys are world-readable and cannot be kept secret.",
            "Remove secret keys from client-side code. Use short-lived, scope-limited tokens issued at runtime, "
                    + "proxy privileged calls through your back end, and rotate any key that has been exposed."),

    CREDENTIALS("credentials", "Hardcoded Credentials & Secrets", HIGH, TENTATIVE, true,
            "The script appears to embed passwords, connection strings, private keys or other secrets directly in source.",
            "Hardcoded credentials in client-side code grant attackers direct access to the protected resource "
                    + "(database, account, internal service) and are trivial to extract from the browser.",
            "Never embed credentials in front-end code. Store secrets server-side, inject them through a secure "
                    + "back-end channel, and rotate anything that has been committed or shipped to clients."),

    PII("pii", "Personally Identifiable Information (PII)", MEDIUM, TENTATIVE, true,
            "The script contains values that look like personal data: email addresses, Saudi (+966) or US phone "
                    + "numbers, or payment-card numbers.",
            "Exposed PII can support phishing, account takeover, fraud and privacy-regulation violations "
                    + "(e.g. Saudi PDPL, GDPR). Card data in client code may also raise PCI-DSS concerns.",
            "Avoid embedding real personal data in shipped code or test fixtures. Mask, tokenise or remove it, "
                    + "and confirm any sample data is synthetic."),

    CRYPTO("crypto", "Cryptographic Material, Hashes & Crypto Libraries", LOW, TENTATIVE, true,
            "The script references hash values (MD5/SHA-1/SHA-256/bcrypt), client-side crypto libraries, or "
                    + "weak cryptographic algorithms.",
            "Client-side hashing/encryption is often a false sense of security: keys and logic are visible to "
                    + "attackers, and weak algorithms (MD5, SHA-1, DES, RC4, ECB) can be broken. Exposed hashes may "
                    + "be cracked offline.",
            "Perform security-sensitive cryptography server-side. Replace weak algorithms with modern ones "
                    + "(SHA-256+, AES-GCM, Argon2/bcrypt for passwords) and never rely on client-side crypto for trust."),

    ENDPOINTS("endpoints", "Endpoints, Paths & URLs", INFORMATION, FIRM, true,
            "The script references API endpoints, internal paths, backup files and URLs.",
            "These reveal the application's attack surface — including hidden, internal or administrative routes — "
                    + "which an attacker can use to expand testing and discover unprotected functionality.",
            "Review exposed routes for missing authorisation. Remove references to internal/admin/backup paths "
                    + "from public bundles and ensure every endpoint enforces access control server-side."),

    HOSTS("hosts", "Hosts & IP Addresses", LOW, TENTATIVE, true,
            "The script contains IP addresses (including private/internal ranges) and internal hostnames.",
            "Internal IPs and hostnames leak infrastructure details that aid network mapping, SSRF targeting and "
                    + "lateral movement.",
            "Strip internal addresses and hostnames from client bundles. Reference back-end services via "
                    + "configuration resolved server-side rather than hardcoded values."),

    VULN_LIBS("vuln_libs", "Vulnerable / Outdated JavaScript Libraries", HIGH, FIRM, true,
            "A bundled JavaScript library was identified at a version with known security vulnerabilities or that "
                    + "has reached end-of-life.",
            "Known-vulnerable front-end libraries expose users to documented attacks (commonly DOM XSS and "
                    + "prototype pollution) that have public exploit details and, often, working payloads.",
            "Upgrade each flagged library to a current, supported release. Track front-end dependencies with an "
                    + "SCA/Retire.js process and patch promptly when advisories are published."),

    COMMENTS("comments", "Developer Comments & Suspicious Code", LOW, TENTATIVE, false,
            "The script contains developer comments (TODO/FIXME/SECURITY), debug flags, or dangerous sinks "
                    + "(eval, innerHTML, document.write).",
            "Comments can disclose intent, weaknesses or credentials, debug flags may enable unsafe behaviour, "
                    + "and dangerous sinks are common DOM-XSS entry points.",
            "Strip comments and debug flags from production builds (minifiers can do this). Replace dangerous "
                    + "sinks with safe APIs (textContent, frameworks' built-in escaping) and validate any dynamic HTML."),

    CLOUD("cloud", "Cloud Service URLs", INFORMATION, FIRM, true,
            "The script references cloud storage or service URLs (AWS S3, Azure Blob, Google Cloud Storage, "
                    + "CloudFront, DigitalOcean, Oracle, Alibaba OSS, Firebase, Rackspace, DreamHost).",
            "Cloud buckets and endpoints are frequently misconfigured (public read/write) and reveal "
                    + "infrastructure. Each referenced bucket is worth checking for open or unauthenticated access.",
            "Verify every referenced bucket/endpoint enforces authentication and correct ACLs, and remove "
                    + "references that are not required by the client."),

    SUBDOMAINS("subdomains", "Subdomains (passive)", INFORMATION, FIRM, true,
            "Subdomains of the target's registrable domain were found referenced inside static files.",
            "Referenced subdomains expand the attack surface and may include forgotten or dangling hosts "
                    + "vulnerable to subdomain takeover, or services that should not be publicly known.",
            "Review each subdomain for exposure and decommission unused DNS records to prevent takeover."),

    SOURCE_MAPS("source_maps", "JavaScript Source Maps", LOW, FIRM, true,
            "Source map (.map) references or inline base64 source maps were found. These can reconstruct the "
                    + "original, pre-minified source including file structure and comments.",
            "Source maps expose original source code, internal paths, comments and application logic, "
                    + "significantly aiding reverse-engineering and vulnerability discovery.",
            "Do not deploy source maps to production, or restrict access to them. Strip sourceMappingURL "
                    + "references from public bundles."),

    DEP_CONFUSION("dep_confusion", "Potential Dependency Confusion", HIGH, FIRM, true,
            "A referenced package or organization appears to be unclaimed on the public NPM registry.",
            "An attacker could publish a malicious package under the unclaimed name; internal builds may then "
                    + "fetch it instead of the intended private package, leading to supply-chain compromise.",
            "Claim the package/scope on the public registry, pin internal registries, and configure scoped "
                    + "registry routing so private names never resolve publicly.");

    private final String key;
    private final String title;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final boolean defaultOn;
    private final String description;
    private final String impact;
    private final String remediation;

    Category(String key, String title, AuditIssueSeverity severity, AuditIssueConfidence confidence,
             boolean defaultOn, String description, String impact, String remediation) {
        this.key = key;
        this.title = title;
        this.severity = severity;
        this.confidence = confidence;
        this.defaultOn = defaultOn;
        this.description = description;
        this.impact = impact;
        this.remediation = remediation;
    }

    public String key() { return key; }
    public String title() { return title; }
    public AuditIssueSeverity severity() { return severity; }
    public AuditIssueConfidence confidence() { return confidence; }
    public boolean defaultOn() { return defaultOn; }
    public String description() { return description; }
    public String impact() { return impact; }
    public String remediation() { return remediation; }

    /** Combined "background" text shown in the issue advisory. */
    public String background() {
        return "<p>" + description + "</p><p><b>Impact:</b> " + impact + "</p>";
    }

    public static Category fromKey(String k) {
        for (Category c : values()) {
            if (c.key.equals(k)) {
                return c;
            }
        }
        return null;
    }
}
