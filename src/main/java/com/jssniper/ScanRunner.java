package com.jssniper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared scanning service used by the context menu and the Results-tab buttons.
 * Each issue is pushed to the {@link ResultsStore} (shown in our own tab, which
 * is what works in Community Edition) and also added to Burp's site map (shown
 * in the Issues panel in Professional).
 */
public class ScanRunner {

    private static final String[] STATIC_EXT = {
            ".js", ".mjs", ".jsx", ".json", ".map", ".css", ".xml", ".svg", ".txt", ".html"
    };

    private final MontoyaApi api;
    private final JsScanCheck scanCheck;
    private final ScanConfig config;
    private final ResultsStore results;

    public ScanRunner(MontoyaApi api, JsScanCheck scanCheck, ScanConfig config, ResultsStore results) {
        this.api = api;
        this.scanCheck = scanCheck;
        this.config = config;
        this.results = results;
    }

    public int scanSelected(List<HttpRequestResponse> selected) {
        ActiveAnalyzer active = new ActiveAnalyzer(api, config);
        int total = 0;
        for (HttpRequestResponse rr : selected) {
            total += record(scanCheck.scan(rr), rr);
            if (scanCheck.looksRelevant(rr)) {
                total += record(active.analyze(rr), rr);
            }
        }
        api.logging().logToOutput("JSsniper: " + total + " finding(s) from "
                + selected.size() + " selected response(s). See the JSsniper > Results tab.");
        return total;
    }

    public int scanHosts(Set<String> hosts) {
        if (hosts.isEmpty()) {
            api.logging().logToOutput("JSsniper: could not determine host from selection.");
            return 0;
        }
        api.logging().logToOutput("JSsniper: scanning host(s) " + String.join(", ", hosts) + " ...");
        return scanFiltered(hosts);
    }

    public int scanEntireSiteMap() {
        api.logging().logToOutput("JSsniper: scanning entire site map ...");
        return scanFiltered(null);
    }

    /** Scan all relevant responses in the site map (optionally restricted to hosts). */
    private int scanFiltered(Set<String> hosts) {
        ActiveAnalyzer active = new ActiveAnalyzer(api, config);
        Set<String> visited = new HashSet<>();
        int scanned = 0;
        int total = 0;

        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String host;
            try {
                host = rr.httpService().host();
            } catch (Exception e) {
                continue;
            }
            if (hosts != null && (host == null || !hosts.contains(host))) {
                continue;
            }
            if (!scanCheck.looksRelevant(rr)) {
                continue;
            }
            String url = rr.request() != null ? rr.request().url() : null;
            if (url != null && !visited.add(url)) {
                continue;
            }
            total += record(scanCheck.scan(rr), rr);
            total += record(active.analyze(rr), rr);
            scanned++;
        }

        api.logging().logToOutput("JSsniper scan complete: " + scanned
                + " static response(s) analysed, " + total + " finding(s). See JSsniper > Results.");
        return total;
    }

    private int record(List<AuditIssue> issues, HttpRequestResponse rr) {
        int n = 0;
        for (AuditIssue issue : issues) {
            results.add(issue, rr);
            try {
                api.siteMap().add(issue); // visible in Burp Pro; harmless in Community
            } catch (Exception ignored) {
                // Community may reject; the Results tab still shows it
            }
            n++;
        }
        return n;
    }

    public void dumpStatic(Set<String> hosts) {
        if (hosts.isEmpty()) {
            api.logging().logToOutput("JSsniper: could not determine host from selection.");
            return;
        }
        Path base = Path.of(System.getProperty("java.io.tmpdir"),
                "jssniper-dump-" + System.currentTimeMillis());
        Set<String> visited = new HashSet<>();
        int written = 0;

        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String host;
            String url;
            try {
                host = rr.httpService().host();
                url = rr.request() != null ? rr.request().url() : null;
            } catch (Exception e) {
                continue;
            }
            if (host == null || url == null || !hosts.contains(host) || !isStatic(url) || !visited.add(url)) {
                continue;
            }
            HttpResponse response = rr.response();
            if (response == null) {
                continue;
            }
            try {
                Path target = base.resolve(relativePath(url));
                Files.createDirectories(target.getParent());
                Files.write(target, response.bodyToString().getBytes(StandardCharsets.UTF_8));
                written++;
            } catch (Exception e) {
                api.logging().logToError("dump error for " + url + ": " + e.getMessage());
            }
        }
        api.logging().logToOutput("JSsniper: dumped " + written + " static file(s) to " + base);
    }

    private static boolean isStatic(String url) {
        String path = url.toLowerCase();
        int q = path.indexOf('?');
        if (q >= 0) {
            path = path.substring(0, q);
        }
        for (String ext : STATIC_EXT) {
            if (path.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static String relativePath(String url) {
        String host = "unknown-host";
        String path = "/index";
        try {
            URI u = URI.create(url);
            if (u.getHost() != null) {
                host = u.getHost();
            }
            if (u.getRawPath() != null && !u.getRawPath().isEmpty() && !u.getRawPath().equals("/")) {
                path = u.getRawPath();
            }
        } catch (Exception ignored) {
            // defaults
        }
        String safe = (host + path).replace("..", "_").replaceAll("[^A-Za-z0-9._/\\-]", "_");
        return safe.startsWith("/") ? safe.substring(1) : safe;
    }
}
