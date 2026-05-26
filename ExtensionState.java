package burp.extension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpHandlerResult;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public class ExtensionState {
    private volatile boolean autoScan;
    private volatile boolean scanPassiveOnly;
    private volatile int maxConcurrentScans;
    private volatile boolean enabled;

    public ExtensionState() {
        this.autoScan = true;
        this.scanPassiveOnly = false;
        this.maxConcurrentScans = 4;
        this.enabled = true;
    }

    public boolean isAutoScan() {
        return autoScan;
    }

    public void setAutoScan(boolean autoScan) {
        this.autoScan = autoScan;
    }

    public boolean isScanPassiveOnly() {
        return scanPassiveOnly;
    }

    public void setScanPassiveOnly(boolean scanPassiveOnly) {
        this.scanPassiveOnly = scanPassiveOnly;
    }

    public int getMaxConcurrentScans() {
        return maxConcurrentScans;
    }

    public void setMaxConcurrentScans(int maxConcurrentScans) {
        this.maxConcurrentScans = maxConcurrentScans;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

class UnloadingHandler implements ExtensionUnloadingHandler {
    private ExecutorService executorService;
    private ScannerCore scannerCore;

    public UnloadingHandler(ExecutorService executorService, ScannerCore scannerCore) {
        this.executorService = executorService;
        this.scannerCore = scannerCore;
    }

    @Override
    public void extensionUnloaded() {
        try {
            scannerCore.setScanning(false);
            
            executorService.shutdown();
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    System.err.println("ExecutorService did not terminate");
                }
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

class ScannerSessionHandler implements HttpHandler {
    private MontoyaApi api;
    private ScannerCore scannerCore;

    public ScannerSessionHandler(MontoyaApi api, ScannerCore scannerCore) {
        this.api = api;
        this.scannerCore = scannerCore;
    }

    @Override
    public HttpHandlerResult handleHttpRequest(HttpRequestResponse requestResponse) {
        return HttpHandlerResult.continueWith(requestResponse);
    }

    @Override
    public HttpHandlerResult handleHttpResponse(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse.response() != null) {
                String responseBody = requestResponse.response().bodyAsString();
                
                if (isJavaScriptResponse(requestResponse)) {
                    ScanResults results = scannerCore.analyzeJavaScript(
                        responseBody,
                        requestResponse.request().url()
                    );
                    
                    if (results.getCriticalCount() > 0) {
                        api.logging().logToOutput(
                            String.format(
                                "JSSniper: Found %d potential secrets in %s",
                                results.getCriticalCount(),
                                requestResponse.request().url()
                            )
                        );
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error in session handler: " + e.getMessage());
        }
        
        return HttpHandlerResult.continueWith(requestResponse);
    }

    private boolean isJavaScriptResponse(HttpRequestResponse requestResponse) {
        try {
            for (var header : requestResponse.response().headers()) {
                if (header.name().equalsIgnoreCase("Content-Type")) {
                    String contentType = header.value();
                    return contentType.contains("javascript") || 
                           contentType.contains("text/plain");
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }
}
