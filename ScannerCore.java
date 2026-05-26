package burp.extension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;

public class ScannerCore {

    private MontoyaApi api;
    private ExtensionState extensionState;
    private DetectionPatterns detectionPatterns;
    private volatile boolean isScanning = false;

    public ScannerCore(MontoyaApi api, ExtensionState extensionState) {
        this.api = api;
        this.extensionState = extensionState;
        this.detectionPatterns = new DetectionPatterns();
    }

    public ScanResults analyzeJavaScript(String jsContent, String sourceUrl) {
        ScanResults results = new ScanResults(sourceUrl);
        
        try {
            analyzeSecrets(jsContent, results);
            analyzeEndpoints(jsContent, results);
            analyzeHardcodedValues(jsContent, results);
            analyzeFrameworks(jsContent, results);
            analyzeSuspiciousCode(jsContent, results);
            analyzeCodeQuality(jsContent, results);
        } catch (Exception e) {
            api.logging().logToError("Error analyzing JavaScript: " + e.getMessage());
        }

        return results;
    }

    private void analyzeSecrets(String content, ScanResults results) {
        Map<String, String> secretPatterns = detectionPatterns.getSecretPatterns();
        
        for (Map.Entry<String, String> entry : secretPatterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getValue(), 
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                FindingDetail finding = new FindingDetail(
                    entry.getKey(),
                    matcher.group(0),
                    getLineNumber(content, matcher.start()),
                    SeverityLevel.CRITICAL,
                    getContext(content, matcher.start(), matcher.end())
                );
                results.addSecretFinding(finding);
            }
        }
    }

    private void analyzeEndpoints(String content, ScanResults results) {
        Map<String, String> endpointPatterns = detectionPatterns.getEndpointPatterns();
        
        for (Map.Entry<String, String> entry : endpointPatterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getValue(), 
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                FindingDetail finding = new FindingDetail(
                    entry.getKey(),
                    matcher.group(0),
                    getLineNumber(content, matcher.start()),
                    SeverityLevel.HIGH,
                    getContext(content, matcher.start(), matcher.end())
                );
                
                if (!results.contains(finding)) {
                    results.addEndpointFinding(finding);
                }
            }
        }
    }

    private void analyzeHardcodedValues(String content, ScanResults results) {
        Map<String, String> hardcodedPatterns = detectionPatterns.getHardcodedPatterns();
        
        for (Map.Entry<String, String> entry : hardcodedPatterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getValue(), 
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                FindingDetail finding = new FindingDetail(
                    entry.getKey(),
                    matcher.group(0),
                    getLineNumber(content, matcher.start()),
                    SeverityLevel.MEDIUM,
                    getContext(content, matcher.start(), matcher.end())
                );
                results.addHardcodedFinding(finding);
            }
        }
    }

    private void analyzeFrameworks(String content, ScanResults results) {
        Map<String, String> frameworkPatterns = detectionPatterns.getFrameworkPatterns();
        
        for (Map.Entry<String, String> entry : frameworkPatterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getValue(), 
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                FindingDetail finding = new FindingDetail(
                    entry.getKey(),
                    matcher.group(0),
                    getLineNumber(content, matcher.start()),
                    SeverityLevel.INFO,
                    getContext(content, matcher.start(), matcher.end())
                );
                
                if (!results.contains(finding)) {
                    results.addFrameworkFinding(finding);
                }
            }
        }
    }

    private void analyzeSuspiciousCode(String content, ScanResults results) {
        Map<String, String> suspiciousPatterns = detectionPatterns.getSuspiciousPatterns();
        
        for (Map.Entry<String, String> entry : suspiciousPatterns.entrySet()) {
            Pattern pattern = Pattern.compile(entry.getValue(), 
                Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                FindingDetail finding = new FindingDetail(
                    entry.getKey(),
                    matcher.group(0),
                    getLineNumber(content, matcher.start()),
                    SeverityLevel.MEDIUM,
                    getContext(content, matcher.start(), matcher.end())
                );
                results.addSuspiciousFinding(finding);
            }
        }
    }

    private void analyzeCodeQuality(String content, ScanResults results) {
        if (content.length() > 1000 && content.split("\n").length < 50) {
            results.addQualityIssue("Minified Code", "Code appears to be minified");
        }

        if (content.contains("sourceMappingURL")) {
            results.addQualityIssue("Source Map", "Source map reference found");
        }

        int importCount = 0;
        Pattern importPattern = Pattern.compile("(?:import|require|from)\\s+['\"]", 
            Pattern.MULTILINE);
        Matcher importMatcher = importPattern.matcher(content);
        while (importMatcher.find()) {
            importCount++;
        }

        if (importCount > 20) {
            results.addQualityIssue("High Dependencies", 
                "High number of imports (" + importCount + ")");
        }

        Pattern commentPattern = Pattern.compile("//.*|/\\*.*?\\*/", 
            Pattern.DOTALL);
        Matcher commentMatcher = commentPattern.matcher(content);
        int commentCount = 0;
        while (commentMatcher.find()) {
            commentCount++;
        }

        if (commentCount > 10) {
            results.addQualityIssue("Commented Code", 
                "Large amount of commented code found");
        }
    }

    private int getLineNumber(String content, int position) {
        return content.substring(0, position).split("\n").length;
    }

    private String getContext(String content, int start, int end) {
        int contextStart = Math.max(0, start - 50);
        int contextEnd = Math.min(content.length(), end + 50);
        return content.substring(contextStart, contextEnd).trim();
    }

    public boolean isScanning() {
        return isScanning;
    }

    public void setScanning(boolean scanning) {
        this.isScanning = scanning;
    }

    public ExtensionState getExtensionState() {
        return extensionState;
    }
}
