package com.jssniper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Passive scan check and shared scanning engine. Scans JavaScript responses and
 * inline scripts, applies precision filters (entropy / Luhn / placeholder
 * stop-lists), runs vulnerable-library detection, and produces one rich audit
 * issue per category with response markers highlighting each match.
 */
public class JsScanCheck implements PassiveScanCheck {

    private static final int MAX_MATCH_LEN = 160;
    private static final int MAX_PER_CATEGORY = 250;
    private static final double SECRET_ENTROPY_MIN = 3.0;

    private static final Pattern INLINE_SCRIPT =
            Pattern.compile("<script[^>]*>(.*?)</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    private static final Pattern INLINE_SOURCEMAP = Pattern.compile(
            "(?i)sourceMappingURL=data:application/json(?:;charset=[a-z0-9-]+)?;base64,([A-Za-z0-9+/=]+)");

    private static final Pattern EXTERNAL_SOURCEMAP = Pattern.compile(
            "(?i)sourceMappingURL=(?!data:)([^\\s\"'*]+\\.map)");

    /** Minimal public-suffix help so registrable domains are sane for common multi-level TLDs. */
    private static final Set<String> SECOND_LEVEL_SUFFIXES = Set.of(
            "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au", "org.au",
            "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "com.br", "com.cn", "com.tr",
            "co.in", "co.za", "co.nz", "com.sg", "com.mx");

    /** Patterns whose captured token must clear an entropy bar to count. */
    private static final Set<String> ENTROPY_REQUIRED =
            Set.of("generic_api_key", "bearer_token", "secret_assign", "aws_secret_key", "algolia_admin");

    /** Placeholder values that should not be reported as real secrets. */
    private static final Set<String> PLACEHOLDERS = Set.of(
            "password", "passwd", "pass", "secret", "changeme", "example", "test", "demo",
            "your_api_key", "yourpassword", "your_password", "xxxxxxxx", "null", "undefined",
            "none", "string", "123456", "admin", "placeholder", "redacted", "todo");

    // IPv4 candidate: not preceded/followed by a word char or dot (kills version
    // strings like v1.2.3.4 and longer sequences like 1.2.3.4.5).
    private static final Pattern IP_CANDIDATE = Pattern.compile(
            "(?<![\\w.])((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}"
            + "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))(?![\\w.])");

    // File extensions that masquerade as email TLDs (e.g. logo@2x.png).
    private static final Set<String> ASSET_TLDS = Set.of(
            "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "css", "js", "mjs",
            "json", "map", "woff", "woff2", "ttf", "eot", "html", "htm", "mp4", "webm");

    private final MontoyaApi api;
    private final ScanConfig config;
    private final PatternStore store;
    private final LibraryCheck libraries;
    private final ResultsStore results;

    public JsScanCheck(MontoyaApi api, ScanConfig config, PatternStore store,
                       LibraryCheck libraries, ResultsStore results) {
        this.api = api;
        this.config = config;
        this.store = store;
        this.libraries = libraries;
        this.results = results;
    }

    @Override
    public String checkName() {
        return "JSsniper";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        try {
            List<AuditIssue> issues = scan(baseRequestResponse);
            for (AuditIssue issue : issues) {
                results.add(issue, baseRequestResponse);
            }
            return auditResult(issues);
        } catch (Exception e) {
            api.logging().logToError("doCheck error: " + e.getMessage());
            return auditResult(List.of());
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        boolean same = newIssue.name().equals(existingIssue.name())
                && newIssue.baseUrl().equals(existingIssue.baseUrl());
        return same ? KEEP_EXISTING : KEEP_BOTH;
    }

    // -----------------------------------------------------------------------
    // Core engine (shared by passive audit and the context-menu scans)
    // -----------------------------------------------------------------------

    /** Quick pre-filter so host scans skip non-JS responses cheaply. */
    public boolean looksRelevant(HttpRequestResponse rr) {
        HttpResponse response = rr.response();
        if (response == null) {
            return false;
        }
        HttpRequest request = rr.request();
        String url = request != null ? request.url() : "";
        String ct = headerValue(response, "Content-Type");
        if (isJavaScript(ct, url) || isJsonResource(ct, url)) {
            return true;
        }
        return config.scanInlineHtml() && ct != null && ct.toLowerCase().contains("text/html");
    }

    public List<AuditIssue> scan(HttpRequestResponse rr) {
        HttpResponse response = rr.response();
        if (response == null) {
            return List.of();
        }

        HttpRequest request = rr.request();
        String url = request != null ? request.url() : "";

        if (config.inScopeOnly() && url != null && !url.isEmpty() && !api.scope().isInScope(url)) {
            return List.of();
        }

        String contentType = headerValue(response, "Content-Type");
        boolean isJs = isJavaScript(contentType, url);
        boolean isJson = isJsonResource(contentType, url);
        boolean isHtml = contentType != null && contentType.toLowerCase().contains("text/html");

        int bodyOffset = response.bodyOffset();
        String body = response.bodyToString();

        String host = null;
        try {
            host = rr.httpService().host();
        } catch (Exception ignored) {
            // host stays null
        }

        List<Segment> segments = new ArrayList<>();
        if (isJs || isJson) {
            segments.add(new Segment(body, bodyOffset));
        } else if (isHtml && config.scanInlineHtml()) {
            Matcher m = INLINE_SCRIPT.matcher(body);
            while (m.find()) {
                String inner = m.group(1);
                if (inner != null && !inner.isBlank()) {
                    segments.add(new Segment(inner, bodyOffset + m.start(1)));
                }
            }
        }
        if (segments.isEmpty()) {
            return List.of();
        }

        Map<Category, List<Finding>> findings = new EnumMap<>(Category.class);
        Map<Category, List<Marker>> markers = new EnumMap<>(Category.class);
        Set<String> seen = new HashSet<>();

        String registrable = registrableDomain(host);
        for (Segment seg : segments) {
            scanPatterns(seg, findings, markers, seen);
            scanLibraries(seg, findings, markers, seen);
            detectSubdomains(seg, host, registrable, findings, markers, seen);
            detectSourceMaps(seg, findings, markers, seen);
            detectIps(seg, findings, markers, seen);
        }

        if (findings.isEmpty()) {
            return List.of();
        }

        List<AuditIssue> issues = new ArrayList<>();
        for (Map.Entry<Category, List<Finding>> entry : findings.entrySet()) {
            Category category = entry.getKey();
            HttpRequestResponse marked = rr.withResponseMarkers(markers.getOrDefault(category, List.of()));
            issues.add(auditIssue(
                    "JSsniper: " + category.title(),
                    buildDetail(category, entry.getValue()),
                    category.remediation(),
                    url,
                    category.severity(),
                    category.confidence(),
                    category.background(),
                    category.remediation(),
                    category.severity(),
                    marked));
        }
        return issues;
    }

    private void scanPatterns(Segment seg, Map<Category, List<Finding>> findings,
                              Map<Category, List<Marker>> markers, Set<String> seen) {
        for (PatternStore.CompiledPattern cp : store.all()) {
            if (!config.isEnabled(cp.category())) {
                continue;
            }
            Matcher m = cp.pattern().matcher(seg.text());
            while (m.find()) {
                String match = m.group();
                if (match == null || match.isEmpty()) {
                    continue;
                }
                String captured = (m.groupCount() >= 1 && m.group(1) != null) ? m.group(1) : match;
                if (!accept(cp.name(), match, captured)) {
                    continue;
                }
                String shortMatch = truncate(match);
                String key = cp.category().key() + "|" + cp.name() + "|" + shortMatch;
                if (!seen.add(key)) {
                    continue;
                }
                List<Finding> list = findings.computeIfAbsent(cp.category(), k -> new ArrayList<>());
                if (list.size() >= MAX_PER_CATEGORY) {
                    continue;
                }
                list.add(new Finding(cp.name(), lineNumber(seg.text(), m.start()), shortMatch, null));
                markers.computeIfAbsent(cp.category(), k -> new ArrayList<>())
                        .add(Marker.marker(seg.offset() + m.start(), seg.offset() + m.end()));
            }
        }
    }

    private void scanLibraries(Segment seg, Map<Category, List<Finding>> findings,
                               Map<Category, List<Marker>> markers, Set<String> seen) {
        if (!config.isEnabled(Category.VULN_LIBS)) {
            return;
        }
        for (LibraryCheck.LibRule rule : libraries.rules()) {
            Matcher m = rule.pattern().matcher(seg.text());
            while (m.find()) {
                if (m.groupCount() < 1 || m.group(1) == null) {
                    continue;
                }
                String version = m.group(1);
                if (LibraryCheck.compareVersions(version, rule.safeVersion()) >= 0) {
                    continue;
                }
                String key = "vuln_libs|" + rule.name() + "|" + version;
                if (!seen.add(key)) {
                    continue;
                }
                List<Finding> list = findings.computeIfAbsent(Category.VULN_LIBS, k -> new ArrayList<>());
                if (list.size() >= MAX_PER_CATEGORY) {
                    continue;
                }
                list.add(new Finding(rule.name() + " " + version,
                        lineNumber(seg.text(), m.start()), truncate(m.group()), rule.summary()));
                markers.computeIfAbsent(Category.VULN_LIBS, k -> new ArrayList<>())
                        .add(Marker.marker(seg.offset() + m.start(1), seg.offset() + m.end(1)));
            }
        }
    }

    private void detectIps(Segment seg, Map<Category, List<Finding>> findings,
                           Map<Category, List<Marker>> markers, Set<String> seen) {
        if (!config.isEnabled(Category.HOSTS)) {
            return;
        }
        Matcher m = IP_CANDIDATE.matcher(seg.text());
        while (m.find()) {
            String ip = m.group(1);
            if (looksLikeVersion(seg.text(), m.start(1)) || versionSuffix(seg.text(), m.end(1))) {
                continue; // e.g. "version 4.17.21.9" or "1.2.3.4-beta"
            }
            String label = classifyIp(ip);
            if (label == null) {
                continue; // invalid / mask / loopback / multicast / example -> dropped
            }
            String key = "hosts|ip|" + ip;
            if (!seen.add(key)) {
                continue;
            }
            List<Finding> list = findings.computeIfAbsent(Category.HOSTS, k -> new ArrayList<>());
            if (list.size() >= MAX_PER_CATEGORY) {
                continue;
            }
            list.add(new Finding(label, lineNumber(seg.text(), m.start(1)), ip, null));
            markers.computeIfAbsent(Category.HOSTS, k -> new ArrayList<>())
                    .add(Marker.marker(seg.offset() + m.start(1), seg.offset() + m.end(1)));
        }
    }

    /** Returns a label for a real-looking IPv4 host, or null to discard noise. */
    static String classifyIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        int[] o = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                o[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return null;
            }
            if (o[i] < 0 || o[i] > 255) {
                return null;
            }
        }
        if (o[0] == 0 || o[0] >= 224) {
            return null; // "this" network, multicast (224-239), reserved (240-255)
        }
        if (o[0] == 127) {
            return null; // loopback - almost always noise in shipped JS
        }
        long v = ((long) o[0] << 24) | ((long) o[1] << 16) | ((long) o[2] << 8) | o[3];
        if (v == 0L || v == 0xFFFFFFFFL) {
            return null; // 0.0.0.0 / 255.255.255.255
        }
        if (isNetmask(v)) {
            return null; // subnet mask (e.g. 255.255.255.0), not a host
        }
        if (o[0] == 1 && o[1] == 2 && o[2] == 3 && o[3] == 4) {
            return null; // classic example IP
        }
        if (o[1] == o[0] + 1 && o[2] == o[1] + 1 && o[3] == o[2] + 1) {
            return null; // strictly sequential octets (e.g. 2.3.4.5) -> version-like, not an IP
        }
        if ((o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)) {
            return null; // RFC 5737 documentation ranges
        }
        if (o[0] == 10
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                || (o[0] == 192 && o[1] == 168)) {
            return "private IP";
        }
        if (o[0] == 169 && o[1] == 254) {
            return "link-local IP";
        }
        if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) {
            return "CGNAT IP";
        }
        return "public IP";
    }

    /** True if the 32-bit value is a contiguous netmask (1^n 0^m). */
    static boolean isNetmask(long v) {
        long inv = (~v) & 0xFFFFFFFFL;
        return (inv & (inv + 1)) == 0L;
    }

    private static final Pattern VERSION_CTX =
            Pattern.compile("(?i)(?:version|release|revision|build|ver|rev|patch|update|sdk|engine|"
                    + "schema|chrome|firefox|webkit|node|\\bv\\.?)\\s*[=:/]?\\s*$");

    /** True if the text just before {@code start} looks like a version prefix. */
    static boolean looksLikeVersion(String text, int start) {
        int from = Math.max(0, start - 24);
        return VERSION_CTX.matcher(text.substring(from, start)).find();
    }

    private static final Pattern VERSION_SUFFIX =
            Pattern.compile("(?i)^-(?:beta|alpha|rc|snapshot|dev|build|final|[0-9])");

    /** True if the bytes right after the quad look like a version suffix (e.g. 1.2.3.4-beta). */
    static boolean versionSuffix(String text, int end) {
        int to = Math.min(text.length(), end + 10);
        return end < text.length() && VERSION_SUFFIX.matcher(text.substring(end, to)).find();
    }

    private void detectSubdomains(Segment seg, String host, String registrable,
                                  Map<Category, List<Finding>> findings,
                                  Map<Category, List<Marker>> markers, Set<String> seen) {
        if (!config.isEnabled(Category.SUBDOMAINS) || registrable == null) {
            return;
        }
        Pattern p = Pattern.compile("(?i)\\b((?:[a-z0-9_-]+\\.)+"
                + Pattern.quote(registrable) + ")\\b");
        Matcher m = p.matcher(seg.text());
        while (m.find()) {
            String fqdn = m.group(1).toLowerCase();
            if (fqdn.equals(registrable) || fqdn.equals(host)) {
                continue;
            }
            String key = "subdomains||" + fqdn;
            if (!seen.add(key)) {
                continue;
            }
            List<Finding> list = findings.computeIfAbsent(Category.SUBDOMAINS, k -> new ArrayList<>());
            if (list.size() >= MAX_PER_CATEGORY) {
                continue;
            }
            list.add(new Finding("subdomain", lineNumber(seg.text(), m.start()), fqdn, null));
            markers.computeIfAbsent(Category.SUBDOMAINS, k -> new ArrayList<>())
                    .add(Marker.marker(seg.offset() + m.start(1), seg.offset() + m.end(1)));
        }
    }

    private void detectSourceMaps(Segment seg, Map<Category, List<Finding>> findings,
                                  Map<Category, List<Marker>> markers, Set<String> seen) {
        if (!config.isEnabled(Category.SOURCE_MAPS)) {
            return;
        }
        // Inline base64 source maps
        Matcher inline = INLINE_SOURCEMAP.matcher(seg.text());
        while (inline.find()) {
            String b64 = inline.group(1);
            String note;
            try {
                String json = new String(java.util.Base64.getDecoder().decode(b64),
                        java.nio.charset.StandardCharsets.UTF_8);
                int sources = countSources(json);
                boolean hasContent = json.contains("\"sourcesContent\"");
                note = "inline base64 source map \u2014 " + sources + " original source path(s)"
                        + (hasContent ? ", original source code embedded (recoverable)" : "");
            } catch (Exception e) {
                note = "inline base64 source map (could not decode)";
            }
            String key = "source_maps|inline|" + Integer.toHexString(b64.hashCode());
            if (seen.add(key)) {
                findings.computeIfAbsent(Category.SOURCE_MAPS, k -> new ArrayList<>())
                        .add(new Finding("inline_source_map", lineNumber(seg.text(), inline.start()), "", note));
                markers.computeIfAbsent(Category.SOURCE_MAPS, k -> new ArrayList<>())
                        .add(Marker.marker(seg.offset() + inline.start(), seg.offset() + inline.end()));
            }
        }
        // External .map references (the active host scan can fetch these)
        Matcher ext = EXTERNAL_SOURCEMAP.matcher(seg.text());
        while (ext.find()) {
            String ref = ext.group(1).trim();
            String key = "source_maps|ext|" + ref;
            if (seen.add(key)) {
                findings.computeIfAbsent(Category.SOURCE_MAPS, k -> new ArrayList<>())
                        .add(new Finding("source_map_reference", lineNumber(seg.text(), ext.start()),
                                ref, "external source map referenced (try fetching it)"));
                markers.computeIfAbsent(Category.SOURCE_MAPS, k -> new ArrayList<>())
                        .add(Marker.marker(seg.offset() + ext.start(1), seg.offset() + ext.end(1)));
            }
        }
    }

    private static int countSources(String mapJson) {
        Matcher arr = Pattern.compile("\"sources\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(mapJson);
        if (!arr.find()) {
            return 0;
        }
        Matcher items = Pattern.compile("\"(?:[^\"\\\\]|\\\\.)*\"").matcher(arr.group(1));
        int n = 0;
        while (items.find()) {
            n++;
        }
        return n;
    }

    /** Precision filters that cut common false positives. */
    private boolean accept(String patternName, String fullMatch, String captured) {
        if ("credit_card".equals(patternName)) {
            return luhnValid(fullMatch);
        }
        if (ENTROPY_REQUIRED.contains(patternName)) {
            return captured.length() >= 12 && Entropy.shannon(captured) >= SECRET_ENTROPY_MIN;
        }
        if ("password_assign".equals(patternName) || "secret_assign".equals(patternName)) {
            return !PLACEHOLDERS.contains(captured.toLowerCase());
        }
        if ("email".equals(patternName)) {
            int dot = fullMatch.lastIndexOf('.');
            if (dot >= 0) {
                String tld = fullMatch.substring(dot + 1).toLowerCase();
                if (ASSET_TLDS.contains(tld)) {
                    return false; // asset reference (e.g. logo@2x.png), not an email
                }
            }
            return true;
        }
        return true;
    }

    private static boolean luhnValid(String candidate) {
        String digits = candidate.replaceAll("\\D", "");
        if (digits.length() < 13 || digits.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean alt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (alt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            alt = !alt;
        }
        return sum % 10 == 0;
    }

    private record Segment(String text, int offset) { }

    private record Finding(String type, int line, String match, String note) { }

    private static boolean isJavaScript(String contentType, String url) {
        if (contentType != null) {
            String c = contentType.toLowerCase();
            if (c.contains("javascript") || c.contains("ecmascript")) {
                return true;
            }
        }
        if (url != null) {
            String path = url.toLowerCase();
            int q = path.indexOf('?');
            if (q >= 0) {
                path = path.substring(0, q);
            }
            return path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".jsx");
        }
        return false;
    }

    private static boolean isJsonResource(String contentType, String url) {
        if (contentType != null && contentType.toLowerCase().contains("json")) {
            return true;
        }
        if (url != null) {
            String path = url.toLowerCase();
            int q = path.indexOf('?');
            if (q >= 0) {
                path = path.substring(0, q);
            }
            return path.endsWith(".json") || path.endsWith(".map");
        }
        return false;
    }

    static String registrableDomain(String host) {
        if (host == null || host.isEmpty() || host.indexOf('.') < 0) {
            return null;
        }
        // Skip raw IPs.
        if (host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
            return null;
        }
        String h = host.toLowerCase();
        String[] labels = h.split("\\.");
        if (labels.length < 2) {
            return null;
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        if (labels.length >= 3 && SECOND_LEVEL_SUFFIXES.contains(lastTwo)) {
            return labels[labels.length - 3] + "." + lastTwo;
        }
        return lastTwo;
    }

    private static String headerValue(HttpResponse response, String name) {
        try {
            return response.headerValue(name);
        } catch (Exception e) {
            return null;
        }
    }

    private static int lineNumber(String text, int index) {
        int line = 1;
        int limit = Math.min(index, text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }

    private static String truncate(String s) {
        return s.length() > MAX_MATCH_LEN ? s.substring(0, MAX_MATCH_LEN) + "\u2026" : s;
    }

    private static String buildDetail(Category category, List<Finding> items) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>JSsniper identified <b>").append(items.size())
                .append("</b> item(s) in this JavaScript for <b>")
                .append(escape(category.title())).append("</b>.</p><ul>");
        for (Finding f : items) {
            if (f.note() != null) {
                sb.append("<li><b>").append(escape(f.type())).append("</b> (line ").append(f.line())
                        .append(") \u2014 ").append(escape(f.note())).append("</li>");
            } else {
                sb.append("<li><b>").append(escape(f.type())).append("</b> (line ").append(f.line())
                        .append("): <code>").append(escape(f.match())).append("</code></li>");
            }
        }
        sb.append("</ul><p>Matches are highlighted in the response. Detection is pattern/heuristic based; "
                + "verify each item before reporting.</p>");
        return sb.toString();
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
