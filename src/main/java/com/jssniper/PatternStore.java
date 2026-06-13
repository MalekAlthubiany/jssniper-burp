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
 * Loads detection patterns from the bundled {@code patterns.tsv} resource and
 * pre-compiles them. Keeping patterns in a resource (rather than Java string
 * literals) avoids a second layer of backslash escaping.
 */
public class PatternStore {

    /** A single compiled detection pattern. */
    public record CompiledPattern(Category category, String name, Pattern pattern) { }

    private static final String RESOURCE = "/patterns.tsv";

    private final List<CompiledPattern> patterns;

    private PatternStore(List<CompiledPattern> patterns) {
        this.patterns = patterns;
    }

    public List<CompiledPattern> all() {
        return patterns;
    }

    public int size() {
        return patterns.size();
    }

    public static PatternStore loadDefault(MontoyaApi api) {
        List<CompiledPattern> list = new ArrayList<>();
        try (InputStream in = PatternStore.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                api.logging().logToError("patterns.tsv not found on classpath");
                return new PatternStore(list);
            }
            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isBlank() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split("\t", 3);
                    if (parts.length < 3) {
                        continue;
                    }
                    Category category = Category.fromKey(parts[0].trim());
                    if (category == null) {
                        continue;
                    }
                    try {
                        Pattern p = Pattern.compile(parts[2], Pattern.MULTILINE);
                        list.add(new CompiledPattern(category, parts[1].trim(), p));
                    } catch (RuntimeException e) {
                        api.logging().logToError(
                                "Bad pattern " + parts[0] + "/" + parts[1] + ": " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load patterns: " + e.getMessage());
        }
        return new PatternStore(list);
    }
}
