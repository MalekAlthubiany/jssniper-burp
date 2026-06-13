package com.jssniper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal, dependency-free parsing of JavaScript source maps. Extracts inline
 * base64 maps from a script body and pulls the {@code sources} and
 * {@code sourcesContent} arrays out of source-map JSON (no external JSON lib,
 * so we tolerate the large/minified maps seen in the wild).
 */
public final class SourceMapParser {

    private SourceMapParser() { }

    /** An inline base64 source map located in a script body. */
    public record InlineMap(String json, int start, int end) { }

    private static final Pattern INLINE_B64 = Pattern.compile(
            "sourceMappingURL=data:application/json;(?:charset=[^;,]+;)?base64,([A-Za-z0-9+/=]+)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern MAP_REF = Pattern.compile(
            "sourceMappingURL=([^\\s'\"*]+\\.map)", Pattern.CASE_INSENSITIVE);

    /** Find and decode inline base64 source maps in a script body. */
    public static List<InlineMap> findInline(String body) {
        List<InlineMap> out = new ArrayList<>();
        Matcher m = INLINE_B64.matcher(body);
        while (m.find()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(m.group(1));
                String json = new String(decoded, StandardCharsets.UTF_8);
                if (looksLikeMap(json)) {
                    out.add(new InlineMap(json, m.start(), m.end()));
                }
            } catch (IllegalArgumentException ignored) {
                // not valid base64; skip
            }
        }
        return out;
    }

    /** Return a referenced external ".map" URL fragment, if present. */
    public static String findMapReference(String body) {
        Matcher m = MAP_REF.matcher(body);
        return m.find() ? m.group(1) : null;
    }

    public static boolean looksLikeMap(String json) {
        return json != null && json.contains("\"version\"") && json.contains("\"sources\"");
    }

    public static List<String> sources(String json) {
        return namedArray(json, "sources");
    }

    public static List<String> sourcesContent(String json) {
        return namedArray(json, "sourcesContent");
    }

    /**
     * Extract a top-level array of strings (and nulls) for the given key.
     * Null JSON elements are returned as Java {@code null} so callers can align
     * {@code sources} with {@code sourcesContent} by index.
     */
    public static List<String> namedArray(String json, String key) {
        List<String> out = new ArrayList<>();
        if (json == null) {
            return out;
        }
        int k = json.indexOf("\"" + key + "\"");
        if (k < 0) {
            return out;
        }
        int open = json.indexOf('[', k);
        if (open < 0) {
            return out;
        }
        int i = open + 1;
        int depth = 1;
        int n = json.length();
        while (i < n && depth > 0) {
            char c = json.charAt(i);
            if (c == '"') {
                StringBuilder sb = new StringBuilder();
                i++;
                while (i < n) {
                    char d = json.charAt(i);
                    if (d == '\\' && i + 1 < n) {
                        char e = json.charAt(i + 1);
                        switch (e) {
                            case 'n' -> sb.append('\n');
                            case 't' -> sb.append('\t');
                            case 'r' -> sb.append('\r');
                            case '"' -> sb.append('"');
                            case '\\' -> sb.append('\\');
                            case '/' -> sb.append('/');
                            case 'b' -> sb.append('\b');
                            case 'f' -> sb.append('\f');
                            case 'u' -> {
                                if (i + 5 < n) {
                                    try {
                                        sb.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                                    } catch (NumberFormatException ignored) {
                                        // leave as-is
                                    }
                                    i += 4;
                                }
                            }
                            default -> sb.append(e);
                        }
                        i += 2;
                    } else if (d == '"') {
                        i++;
                        break;
                    } else {
                        sb.append(d);
                        i++;
                    }
                }
                out.add(sb.toString());
            } else if (c == 'n' && json.regionMatches(i, "null", 0, 4)) {
                out.add(null);
                i += 4;
            } else if (c == '[') {
                depth++;
                i++;
            } else if (c == ']') {
                depth--;
                i++;
            } else {
                i++;
            }
        }
        return out;
    }
}
