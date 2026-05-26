package burp.extension;

import java.util.HashMap;
import java.util.Map;

public class DetectionPatterns {

    private Map<String, String> secretPatterns;
    private Map<String, String> endpointPatterns;
    private Map<String, String> hardcodedPatterns;
    private Map<String, String> frameworkPatterns;
    private Map<String, String> suspiciousPatterns;

    public DetectionPatterns() {
        initializeSecretPatterns();
        initializeEndpointPatterns();
        initializeHardcodedPatterns();
        initializeFrameworkPatterns();
        initializeSuspiciousPatterns();
    }

    private void initializeSecretPatterns() {
        secretPatterns = new HashMap<>();
        
        secretPatterns.put("API Keys", 
            "(?:api[_-]?key|apikey|api_secret|secret[_-]?key|access[_-]?key)\\s*[=:]\\s*[\"']?([A-Za-z0-9_\\-\\.]{20,})[\"']?");
        
        secretPatterns.put("AWS Access Keys", 
            "(?:AKIA|aws[_-]?secret|aws[_-]?access)[A-Za-z0-9/_\\-\\.]{20,}(==)?");
        
        secretPatterns.put("GitHub Tokens", 
            "gh[pousr]{1,3}_[A-Za-z0-9_]{36,255}");
        
        secretPatterns.put("Stripe Keys", 
            "(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}");
        
        secretPatterns.put("Twilio SID", 
            "AC[a-zA-Z0-9_]{32}");
        
        secretPatterns.put("Slack Tokens", 
            "xox[baprs]-[0-9a-zA-Z]{10,48}");
        
        secretPatterns.put("Google API Keys", 
            "AIza[0-9A-Za-z\\-_]{35}");
        
        secretPatterns.put("Firebase Keys", 
            "AAAA[A-Za-z0-9_-]{7}");
        
        secretPatterns.put("JWT Tokens", 
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
        
        secretPatterns.put("MongoDB URI", 
            "mongodb(?:\\+srv)?://[^\\s\"']+");
        
        secretPatterns.put("Database Credentials", 
            "(?:db_password|db_pass|password|passwd|pwd)\\s*[=:]\\s*[\"']([^\"']+)[\"']");
        
        secretPatterns.put("Private Keys", 
            "(?:-----BEGIN|PRIVATE KEY)[^-]{20,}");
        
        secretPatterns.put("Bearer Tokens", 
            "(?:bearer|authorization|auth|token)\\s*[=:]\\s*[\"']?([A-Za-z0-9\\-_.]{20,})[\"']?");
    }

    private void initializeEndpointPatterns() {
        endpointPatterns = new HashMap<>();
        
        endpointPatterns.put("API Routes", 
            "/(?:api|v[0-9]|graphql|rest|rpc|endpoint|service|data)(?:/[a-zA-Z0-9_\\-/]+)?");
        
        endpointPatterns.put("HTTP Method Calls", 
            "\\.(?:get|post|put|delete|patch|fetch|request)\\([\"']([/a-zA-Z0-9_\\-\\.?&=]+)[\"']");
        
        endpointPatterns.put("AJAX Calls", 
            "\\$\\.(?:ajax|get|post|getJSON)\\s*\\(\\s*[\"']([^'\"]+)");
        
        endpointPatterns.put("Fetch Endpoints", 
            "fetch\\([\"']([^\"']+)");
        
        endpointPatterns.put("Axios Routes", 
            "axios\\.(?:get|post|put|delete|patch)\\([\"']([^\"']+)");
        
        endpointPatterns.put("WebSocket Endpoints", 
            "(?:ws|wss)://[^\\s\"']+");
        
        endpointPatterns.put("Internal Paths", 
            "/(?:admin|api|internal|debug|test|backup|config|settings|upload|download)(?:/[a-zA-Z0-9_\\-/]*)?");
        
        endpointPatterns.put("Backup Files", 
            "/(?:[a-zA-Z0-9_\\-]+)?\\.(?:bak|backup|old|tmp|swp|sql|db)");
    }

    private void initializeHardcodedPatterns() {
        hardcodedPatterns = new HashMap<>();
        
        hardcodedPatterns.put("IP Addresses", 
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
        
        hardcodedPatterns.put("Internal IPs", 
            "(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|localhost|127\\.0\\.0\\.1)");
        
        hardcodedPatterns.put("Hostnames", 
            "(?:host|hostname|domain|server)\\s*[=:]\\s*[\"']([a-zA-Z0-9\\-\\.]+)[\"']");
        
        hardcodedPatterns.put("Port Numbers", 
            "(?:port|PORT)\\s*[=:]\\s*(?:[0-9]{2,5})");
        
        hardcodedPatterns.put("Usernames", 
            "(?:user|username|uid|user_id)\\s*[=:]\\s*[\"']([a-zA-Z0-9_\\-\\.@]+)[\"']");
        
        hardcodedPatterns.put("Email Addresses", 
            "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    }

    private void initializeFrameworkPatterns() {
        frameworkPatterns = new HashMap<>();
        
        frameworkPatterns.put("jQuery Usage", 
            "jquery[\"']?\\s*,?\\s*[\"']?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
        
        frameworkPatterns.put("Angular.js", 
            "angular\\.js[\"']|angular\\(.*?\\)\\s*\\.(?:module|controller|service)");
        
        frameworkPatterns.put("React Library", 
            "react[\"']?\\s*,?\\s*[\"']?([0-9]+\\.[0-9]+|latest)");
        
        frameworkPatterns.put("Vue.js", 
            "vue[\"']?\\s*,?\\s*[\"']?([0-9]+\\.[0-9]+)");
        
        frameworkPatterns.put("Bootstrap Framework", 
            "bootstrap(?:[\"']?\\s*,?\\s*[\"']?([0-9]+\\.[0-9]+))?");
        
        frameworkPatterns.put("Lodash Library", 
            "(?:lodash|_)[\"']?\\s*,?\\s*[\"']?([0-9]+\\.[0-9]+)?");
        
        frameworkPatterns.put("Moment.js Deprecated", 
            "moment\\.js|moment\\([\"']");
        
        frameworkPatterns.put("XMLHttpRequest", 
            "(?:XMLHttpRequest|new\\s+XMLHttpRequest|ActiveXObject)");
        
        frameworkPatterns.put("Eval Usage", 
            "(?:eval|Function\\()\\s*\\(");
        
        frameworkPatterns.put("Unsafe DOM Operations", 
            "(?:innerHTML|dangerouslySetInnerHTML|outerHTML|insertAdjacentHTML)");
    }

    private void initializeSuspiciousPatterns() {
        suspiciousPatterns = new HashMap<>();
        
        suspiciousPatterns.put("Console Logging", 
            "console\\.(?:log|error|warn|info|debug)\\s*\\(");
        
        suspiciousPatterns.put("Disabled Security Checks", 
            "(?:disable|skip|ignore).*(?:cors|csp|xss|sql|injection)");
        
        suspiciousPatterns.put("Todo Comments", 
            "(?://|/\\*)\\s*(?:TODO|FIXME|HACK|XXX|BUG|SECURITY|VULNERABILITY)");
        
        suspiciousPatterns.put("Base64 Encoding", 
            "[\"']?(?:[A-Za-z0-9+/]{20,}={0,2})[\"']?(?=\\s*[),;\\n])");
        
        suspiciousPatterns.put("Obfuscation Functions", 
            "(?:atob|btoa|unescape|decode|encrypt)");
        
        suspiciousPatterns.put("Debug Mode", 
            "(?:debug|debugMode|DEBUG|dev|development)\\s*[=:]\\s*(?:true|1)");
        
        suspiciousPatterns.put("Admin Functions", 
            "(?:function\\s+)?(?:adminCheck|isAdmin|checkAdmin|requireAdmin)");
    }

    public Map<String, String> getSecretPatterns() {
        return secretPatterns;
    }

    public Map<String, String> getEndpointPatterns() {
        return endpointPatterns;
    }

    public Map<String, String> getHardcodedPatterns() {
        return hardcodedPatterns;
    }

    public Map<String, String> getFrameworkPatterns() {
        return frameworkPatterns;
    }

    public Map<String, String> getSuspiciousPatterns() {
        return suspiciousPatterns;
    }

    public int getTotalPatterns() {
        return secretPatterns.size() + endpointPatterns.size() + 
               hardcodedPatterns.size() + frameworkPatterns.size() + 
               suspiciousPatterns.size();
    }
}
