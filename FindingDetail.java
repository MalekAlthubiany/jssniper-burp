package burp.extension;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ScanResults {
    private String sourceUrl;
    private List<FindingDetail> secretFindings;
    private List<FindingDetail> endpointFindings;
    private List<FindingDetail> hardcodedFindings;
    private List<FindingDetail> frameworkFindings;
    private List<FindingDetail> suspiciousFindings;
    private List<QualityIssue> qualityIssues;
    private long scanTimestamp;
    private boolean isComplete;

    public ScanResults(String sourceUrl) {
        this.sourceUrl = sourceUrl;
        this.secretFindings = new ArrayList<>();
        this.endpointFindings = new ArrayList<>();
        this.hardcodedFindings = new ArrayList<>();
        this.frameworkFindings = new ArrayList<>();
        this.suspiciousFindings = new ArrayList<>();
        this.qualityIssues = new ArrayList<>();
        this.scanTimestamp = System.currentTimeMillis();
        this.isComplete = false;
    }

    public void addSecretFinding(FindingDetail finding) {
        if (!secretFindings.contains(finding)) {
            secretFindings.add(finding);
        }
    }

    public void addEndpointFinding(FindingDetail finding) {
        if (!endpointFindings.contains(finding)) {
            endpointFindings.add(finding);
        }
    }

    public void addHardcodedFinding(FindingDetail finding) {
        if (!hardcodedFindings.contains(finding)) {
            hardcodedFindings.add(finding);
        }
    }

    public void addFrameworkFinding(FindingDetail finding) {
        if (!frameworkFindings.contains(finding)) {
            frameworkFindings.add(finding);
        }
    }

    public void addSuspiciousFinding(FindingDetail finding) {
        if (!suspiciousFindings.contains(finding)) {
            suspiciousFindings.add(finding);
        }
    }

    public void addQualityIssue(String type, String description) {
        qualityIssues.add(new QualityIssue(type, description));
    }

    public boolean contains(FindingDetail finding) {
        return secretFindings.contains(finding) || 
               endpointFindings.contains(finding) ||
               hardcodedFindings.contains(finding) ||
               frameworkFindings.contains(finding) ||
               suspiciousFindings.contains(finding);
    }

    public String getSourceUrl() {
        return sourceUrl;
    }

    public List<FindingDetail> getSecretFindings() {
        return secretFindings;
    }

    public List<FindingDetail> getEndpointFindings() {
        return endpointFindings;
    }

    public List<FindingDetail> getHardcodedFindings() {
        return hardcodedFindings;
    }

    public List<FindingDetail> getFrameworkFindings() {
        return frameworkFindings;
    }

    public List<FindingDetail> getSuspiciousFindings() {
        return suspiciousFindings;
    }

    public List<QualityIssue> getQualityIssues() {
        return qualityIssues;
    }

    public int getTotalFindings() {
        return secretFindings.size() + endpointFindings.size() + 
               hardcodedFindings.size() + suspiciousFindings.size();
    }

    public int getCriticalCount() {
        return secretFindings.size();
    }

    public int getHighCount() {
        return endpointFindings.size();
    }

    public int getMediumCount() {
        return hardcodedFindings.size() + suspiciousFindings.size();
    }

    public int getInfoCount() {
        return frameworkFindings.size() + qualityIssues.size();
    }

    public long getScanTimestamp() {
        return scanTimestamp;
    }

    public void setComplete(boolean complete) {
        this.isComplete = complete;
    }

    public boolean isComplete() {
        return isComplete;
    }
}

class FindingDetail {
    private String type;
    private String match;
    private int lineNumber;
    private SeverityLevel severity;
    private String context;

    public FindingDetail(String type, String match, int lineNumber, 
                       SeverityLevel severity, String context) {
        this.type = type;
        this.match = match;
        this.lineNumber = lineNumber;
        this.severity = severity;
        this.context = context;
    }

    public String getType() {
        return type;
    }

    public String getMatch() {
        return match.length() > 100 ? match.substring(0, 100) + "..." : match;
    }

    public String getFullMatch() {
        return match;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public SeverityLevel getSeverity() {
        return severity;
    }

    public String getContext() {
        return context.length() > 150 ? context.substring(0, 150) + "..." : context;
    }

    public String getFullContext() {
        return context;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FindingDetail)) {
            return false;
        }
        FindingDetail other = (FindingDetail) obj;
        return type.equals(other.type) && match.equals(other.match);
    }

    @Override
    public int hashCode() {
        return (type + match).hashCode();
    }
}

class QualityIssue {
    private String type;
    private String description;

    public QualityIssue(String type, String description) {
        this.type = type;
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public String getDescription() {
        return description;
    }
}

enum SeverityLevel {
    CRITICAL("Critical - Secrets and Keys"),
    HIGH("High - Endpoints and Paths"),
    MEDIUM("Medium - Hardcoded Values and Suspicious Code"),
    INFO("Info - Frameworks and Code Quality"),
    LOW("Low - Informational");

    private String displayName;

    SeverityLevel(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
