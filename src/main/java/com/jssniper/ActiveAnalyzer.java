package com.jssniper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/**
 * Active analysis that issues HTTP requests through Burp's networking stack:
 *   - fetches/guesses JavaScript source maps (.map)
 *   - verifies referenced NPM packages to flag potential dependency confusion
 *
 * Created fresh per host scan so its caches are scoped to that run. Never used
 * from a passive audit (which must not make requests).
 */
public class ActiveAnalyzer {

    private static final int MAX_NPM_QUERIES = 60;
    private static final int MAX_MAP_CANDIDATES = 3;

    private static final Pattern EXTERNAL_REF =
            Pattern.compile("(?i)sourceMappingURL=(?!data:)([^\\s\"'*]+\\.map)");
    private static final Pattern REQUIRE_IMPORT = Pattern.compile(
            "(?:require\\(|import\\s+(?:[^'\"]*?from\\s+)?)[\"']([^\"']+)[\"']");
    private static final Pattern PKG_DEP_BLOCK = Pattern.compile(
            "\"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)\"\\s*:\\s*\\{([^}]*)\\}",
            Pattern.DOTALL);
    private static final Pattern PKG_KEY = Pattern.compile("\"([^\"]+)\"\\s*:");
    private static final Pattern VALID_NPM =
            Pattern.compile("^(?:@[a-z0-9-_.]+/)?[a-z0-9-_.]+$");

    private final MontoyaApi api;
    private final ScanConfig config;
    private final Map<String, Boolean> npmClaimed = new HashMap<>();
    private final Set<String> reportedDeps = new HashSet<>();
    private final Set<String> triedMaps = new HashSet<>();
    private int npmQueries = 0;

    public ActiveAnalyzer(MontoyaApi api, ScanConfig config) {
        this.api = api;
        this.config = config;
    }

    public List<AuditIssue> analyze(HttpRequestResponse jsRr) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpResponse resp = jsRr.response();
        if (resp == null) {
            return issues;
        }
        String url = jsRr.request() != null ? jsRr.request().url() : null;
        String body = resp.bodyToString();
        if (config.isEnabled(Category.SOURCE_MAPS)) {
            issues.addAll(checkSourceMaps(url, body));
        }
        if (config.isEnabled(Category.DEP_CONFUSION)) {
            issues.addAll(checkDependencyConfusion(jsRr, body));
        }
        return issues;
    }

    // --- Source maps --------------------------------------------------------

    private List<AuditIssue> checkSourceMaps(String url, String body) {
        List<AuditIssue> out = new ArrayList<>();
        if (url == null || !url.toLowerCase().contains(".js")) {
            return out;
        }
        Set<String> candidates = new LinkedHashSet<>();
        Matcher m = EXTERNAL_REF.matcher(body);
        while (m.find()) {
            try {
                candidates.add(URI.create(url).resolve(m.group(1).trim()).toString());
            } catch (Exception ignored) {
                // skip unparsable reference
            }
        }
        String base = url.contains("?") ? url.substring(0, url.indexOf('?')) : url;
        candidates.add(base + ".map");

        int tried = 0;
        for (String candidate : candidates) {
            if (tried++ >= MAX_MAP_CANDIDATES || !triedMaps.add(candidate)) {
                continue;
            }
            try {
                HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(candidate));
                HttpResponse r = rr.response();
                if (r == null || r.statusCode() != 200) {
                    continue;
                }
                String mb = r.bodyToString().trim();
                if (!mb.startsWith("{") || !mb.contains("\"sources\"") || !mb.contains("\"version\"")) {
                    continue;
                }
                int sources = countSources(mb);
                boolean hasContent = mb.contains("\"sourcesContent\"");
                String detail = "<p>A JavaScript source map was retrieved at <code>" + esc(candidate)
                        + "</code>, exposing <b>" + sources + "</b> original source path(s)"
                        + (hasContent ? ", with original source code embedded (full recovery possible)" : "")
                        + ".</p>";
                out.add(auditIssue("JSsniper: " + Category.SOURCE_MAPS.title(), detail,
                        Category.SOURCE_MAPS.remediation(), url, Category.SOURCE_MAPS.severity(),
                        Category.SOURCE_MAPS.confidence(), Category.SOURCE_MAPS.background(),
                        Category.SOURCE_MAPS.remediation(), Category.SOURCE_MAPS.severity(), rr));
            } catch (Exception e) {
                api.logging().logToError("source map fetch error: " + e.getMessage());
            }
        }
        return out;
    }

    // --- Dependency confusion ----------------------------------------------

    private List<AuditIssue> checkDependencyConfusion(HttpRequestResponse jsRr, String body) {
        List<AuditIssue> out = new ArrayList<>();
        for (String pkg : extractPackages(body)) {
            if (npmQueries >= MAX_NPM_QUERIES) {
                break;
            }
            if (!reportedDeps.add(pkg)) {
                continue;
            }
            Boolean claimed = npmClaimed.get(pkg);
            if (claimed == null) {
                claimed = isClaimed(pkg);
                npmClaimed.put(pkg, claimed);
                npmQueries++;
            }
            if (Boolean.FALSE.equals(claimed)) {
                String url = jsRr.request() != null ? jsRr.request().url() : "";
                String detail = "<p>The package <code>" + esc(pkg) + "</code> is referenced but appears "
                        + "<b>unclaimed</b> on the public NPM registry (HTTP 404). If this is a private or "
                        + "internal package, an attacker could publish a malicious public package under this "
                        + "name that internal builds may resolve instead.</p>";
                out.add(auditIssue("JSsniper: " + Category.DEP_CONFUSION.title(), detail,
                        Category.DEP_CONFUSION.remediation(), url, Category.DEP_CONFUSION.severity(),
                        Category.DEP_CONFUSION.confidence(), Category.DEP_CONFUSION.background(),
                        Category.DEP_CONFUSION.remediation(), Category.DEP_CONFUSION.severity(),
                        markPackage(jsRr, body, pkg)));
            }
        }
        return out;
    }

    private boolean isClaimed(String pkg) {
        try {
            String enc = pkg.startsWith("@") ? pkg.replace("/", "%2F") : pkg;
            HttpRequestResponse rr = api.http().sendRequest(
                    HttpRequest.httpRequestFromUrl("https://registry.npmjs.org/" + enc));
            HttpResponse r = rr.response();
            if (r == null) {
                return true; // unknown -> assume claimed (avoid false positive)
            }
            return r.statusCode() != 404;
        } catch (Exception e) {
            api.logging().logToError("npm check error: " + e.getMessage());
            return true;
        }
    }

    private Set<String> extractPackages(String body) {
        Set<String> names = new LinkedHashSet<>();
        Matcher ri = REQUIRE_IMPORT.matcher(body);
        while (ri.find()) {
            addPackage(names, ri.group(1));
        }
        Matcher block = PKG_DEP_BLOCK.matcher(body);
        while (block.find()) {
            Matcher key = PKG_KEY.matcher(block.group(1));
            while (key.find()) {
                addPackage(names, key.group(1));
            }
        }
        return names;
    }

    private void addPackage(Set<String> names, String raw) {
        if (raw == null) {
            return;
        }
        String s = raw.trim();
        if (s.isEmpty() || s.startsWith(".") || s.startsWith("/") || s.startsWith("http")) {
            return; // relative or absolute path, not a registry package
        }
        // Reduce to the package root: @scope/name or name (drop sub-paths).
        String root;
        if (s.startsWith("@")) {
            int second = s.indexOf('/', s.indexOf('/') + 1);
            root = second > 0 ? s.substring(0, second) : s;
        } else {
            int slash = s.indexOf('/');
            root = slash > 0 ? s.substring(0, slash) : s;
        }
        root = root.toLowerCase();
        if (VALID_NPM.matcher(root).matches() && root.length() >= 2) {
            names.add(root);
        }
    }

    private HttpRequestResponse markPackage(HttpRequestResponse jsRr, String body, String pkg) {
        try {
            int idx = body.indexOf(pkg);
            if (idx < 0) {
                return jsRr;
            }
            int offset = jsRr.response().bodyOffset() + idx;
            return jsRr.withResponseMarkers(
                    burp.api.montoya.core.Marker.marker(offset, offset + pkg.length()));
        } catch (Exception e) {
            return jsRr;
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

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
