package com.jssniper;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import javax.swing.SwingUtilities;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe store of findings for the JSsniper Results tab. This is how
 * results are shown in Burp Community Edition, which has no scanner/Issues UI.
 */
public class ResultsStore {

    public record Row(String severity, String confidence, String issue, String host,
                      String path, String url, String detailHtml, String remediation,
                      java.util.List<String> evidence, HttpRequestResponse rr, long seq) { }

    private final List<Row> rows = Collections.synchronizedList(new ArrayList<>());
    private final java.util.Set<String> keys = ConcurrentHashMap.newKeySet();
    private static final Pattern CODE = Pattern.compile("<code>(.*?)</code>", Pattern.DOTALL);
    private final AtomicLong seq = new AtomicLong();
    private volatile Runnable listener;

    public void setListener(Runnable r) {
        this.listener = r;
    }

    public void add(AuditIssue issue, HttpRequestResponse rr) {
        String url = issue.baseUrl() != null ? issue.baseUrl() : "";
        String detail = issue.detail() != null ? issue.detail() : "";
        String key = issue.name() + "|" + url + "|" + Integer.toHexString(detail.hashCode());
        if (!keys.add(key)) {
            return;
        }
        String host = "";
        String path = "";
        try {
            URI u = URI.create(url);
            if (u.getHost() != null) {
                host = u.getHost();
            }
            if (u.getRawPath() != null) {
                path = u.getRawPath();
            }
        } catch (Exception ignored) {
            // leave host/path blank
        }
        java.util.List<String> evidence = new ArrayList<>();
        Matcher m = CODE.matcher(detail);
        while (m.find()) {
            evidence.add(unescape(m.group(1)));
        }
        rows.add(new Row(issue.severity().name(), issue.confidence().name(), issue.name(),
                host, path, url, detail, issue.remediation(), evidence, rr, seq.incrementAndGet()));
        fire();
    }

    public List<Row> snapshot() {
        synchronized (rows) {
            return new ArrayList<>(rows);
        }
    }

    public int size() {
        return rows.size();
    }

    public void clear() {
        rows.clear();
        keys.clear();
        fire();
    }

    private static String unescape(String s) {
        return s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"");
    }

    private void fire() {
        Runnable l = listener;
        if (l != null) {
            SwingUtilities.invokeLater(l);
        }
    }
}
