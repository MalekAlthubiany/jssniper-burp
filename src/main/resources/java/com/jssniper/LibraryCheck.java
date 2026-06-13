package com.jssniper;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Detects JavaScript libraries by version and flags versions below a known-safe
 * threshold. Rules are loaded from the bundled {@code libraries.tsv} resource.
 */
public class LibraryCheck {

    /** A single library detector: name, version-extracting pattern, safe version, advisory. */
    public record LibRule(String name, Pattern pattern, String safeVersion, String summary) { }

    private static final String RESOURCE = "/libraries.tsv";

    private final List<LibRule> rules;

    private LibraryCheck(List<LibRule> rules) {
        this.rules = rules;
    }

    public List<LibRule> rules() {
        return rules;
    }

    public int size() {
        return rules.size();
    }

    public static LibraryCheck loadDefault(MontoyaApi api) {
        List<LibRule> list = new ArrayList<>();
        try (InputStream in = LibraryCheck.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                api.logging().logToError("libraries.tsv not found on classpath");
                return new LibraryCheck(list);
            }
            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isBlank() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split("\t", 4);
                    if (parts.length < 4) {
                        continue;
                    }
                    try {
                        Pattern p = Pattern.compile(parts[1], Pattern.CASE_INSENSITIVE);
                        list.add(new LibRule(parts[0].trim(), p, parts[2].trim(), parts[3].trim()));
                    } catch (RuntimeException e) {
                        api.logging().logToError("Bad library rule " + parts[0] + ": " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load libraries: " + e.getMessage());
        }
        return new LibraryCheck(list);
    }

    /** Returns negative if {@code a} is older than {@code b}. Numeric, dot-separated. */
    public static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int x = i < pa.length ? leadingInt(pa[i]) : 0;
            int y = i < pb.length ? leadingInt(pb[i]) : 0;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }

    private static int leadingInt(String s) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) {
                digits.append(c);
            } else {
                break;
            }
        }
        return digits.length() == 0 ? 0 : Integer.parseInt(digits.toString());
    }
}
