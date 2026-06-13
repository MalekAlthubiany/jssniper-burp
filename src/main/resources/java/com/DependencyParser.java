package com.jssniper;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts NPM package names referenced in JavaScript/JSON: from package.json
 * dependency blocks and from require()/import statements. Relative paths, URLs
 * and Node built-ins are excluded so only real registry packages remain.
 */
public final class DependencyParser {

    private DependencyParser() { }

    private static final Pattern DEP_BLOCK = Pattern.compile(
            "\"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)\"\\s*:\\s*\\{([^}]*)\\}",
            Pattern.DOTALL);

    private static final Pattern DEP_KEY = Pattern.compile("\"((?:@[^\"/]+/)?[A-Za-z0-9._-]+)\"\\s*:");

    private static final Pattern REQUIRE = Pattern.compile(
            "require\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)");

    private static final Pattern IMPORT_FROM = Pattern.compile(
            "(?:import|export)\\b[^'\"]*?from\\s*['\"]([^'\"]+)['\"]");

    private static final Pattern IMPORT_BARE = Pattern.compile(
            "import\\s*['\"]([^'\"]+)['\"]");

    private static final Set<String> BUILTINS = Set.of(
            "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
            "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http",
            "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process",
            "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
            "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib");

    public static Set<String> parse(String content) {
        Set<String> packages = new LinkedHashSet<>();

        Matcher block = DEP_BLOCK.matcher(content);
        while (block.find()) {
            Matcher key = DEP_KEY.matcher(block.group(1));
            while (key.find()) {
                addPackage(packages, key.group(1));
            }
        }
        collect(packages, REQUIRE.matcher(content));
        collect(packages, IMPORT_FROM.matcher(content));
        collect(packages, IMPORT_BARE.matcher(content));
        return packages;
    }

    private static void collect(Set<String> out, Matcher m) {
        while (m.find()) {
            addPackage(out, m.group(1));
        }
    }

    private static void addPackage(Set<String> out, String specifier) {
        String name = packageName(specifier);
        if (name != null) {
            out.add(name);
        }
    }

    /** Normalize an import specifier to a registry package name, or null to skip. */
    public static String packageName(String specifier) {
        if (specifier == null || specifier.isBlank()) {
            return null;
        }
        String s = specifier.trim();
        if (s.startsWith(".") || s.startsWith("/") || s.contains(":") || s.startsWith("~")) {
            return null; // relative path, URL, alias
        }
        String name;
        if (s.startsWith("@")) {
            int slash = s.indexOf('/');
            if (slash < 0) {
                return null; // malformed scope
            }
            int second = s.indexOf('/', slash + 1);
            name = second < 0 ? s : s.substring(0, second); // @scope/name
        } else {
            int slash = s.indexOf('/');
            name = slash < 0 ? s : s.substring(0, slash); // strip subpath
        }
        if (BUILTINS.contains(name)) {
            return null;
        }
        if (!name.matches("(?:@[a-z0-9._-]+/)?[a-z0-9._-]+")) {
            return null; // NPM names are lowercase; reject odd specifiers
        }
        return name;
    }

    /** NPM registry URL for a package name (scoped names get the slash encoded). */
    public static String registryUrl(String packageName) {
        return "https://registry.npmjs.org/" + packageName.replace("/", "%2f");
    }
}
