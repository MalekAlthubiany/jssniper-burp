package burp.extension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.SwingUtils;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.ExecutorService;

public class JSniperTab extends JPanel {

    private MontoyaApi api;
    private ScannerCore scannerCore;
    private ExecutorService executorService;
    private ExtensionState extensionState;
    private JTable resultsTable;
    private JTextArea detailsArea;
    private JProgressBar progressBar;
    private JButton scanButton;
    private JButton clearButton;
    private DefaultTableModel tableModel;

    public JSniperTab(MontoyaApi api, ScannerCore scannerCore, 
                      ExecutorService executorService, ExtensionState extensionState) {
        this.api = api;
        this.scannerCore = scannerCore;
        this.executorService = executorService;
        this.extensionState = extensionState;

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        add(createControlPanel(), BorderLayout.NORTH);
        add(createResultsPanel(), BorderLayout.CENTER);

        applyDefaultScanSettings();
    }

    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout());
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        scanButton = new JButton("Scan All JavaScript");
        scanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performScan();
            }
        });
        
        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearResults();
            }
        });
        
        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);
        
        progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setPreferredSize(new Dimension(300, 25));
        
        controlPanel.add(buttonPanel, BorderLayout.WEST);
        controlPanel.add(progressBar, BorderLayout.EAST);
        
        return controlPanel;
    }

    private JPanel createResultsPanel() {
        JPanel resultsPanel = new JPanel(new BorderLayout());
        
        tableModel = new DefaultTableModel(
            new String[]{"Severity", "Type", "Finding", "Line", "Source"}, 
            0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        resultsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        
        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        tableScrollPane.setPreferredSize(new Dimension(800, 300));
        
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setText("Select a finding to view details...");
        
        JScrollPane detailsScrollPane = new JScrollPane(detailsArea);
        detailsScrollPane.setPreferredSize(new Dimension(800, 200));
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, 
            tableScrollPane, detailsScrollPane);
        splitPane.setDividerLocation(300);
        
        resultsPanel.add(splitPane, BorderLayout.CENTER);
        
        return resultsPanel;
    }

    private void performScan() {
        scanButton.setEnabled(false);
        clearButton.setEnabled(false);
        progressBar.setIndeterminate(true);
        
        executorService.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    scanAllHttpMessages();
                    progressBar.setIndeterminate(false);
                    api.logging().logToOutput("Scan completed");
                } catch (Exception e) {
                    api.logging().logToError("Scan failed: " + e.getMessage());
                    e.printStackTrace(api.logging().errorStream());
                } finally {
                    scanButton.setEnabled(true);
                    clearButton.setEnabled(true);
                }
            }
        });
    }

    private void scanAllHttpMessages() {
        try {
            var siteMap = api.http().siteMap();
            int totalMessages = siteMap.size();
            
            for (int i = 0; i < totalMessages; i++) {
                var requestResponse = siteMap.get(i);
                
                if (requestResponse.response() != null) {
                    String responseBody = requestResponse.response().bodyAsString();
                    
                    if (isJavaScript(responseBody, requestResponse)) {
                        ScanResults results = scannerCore.analyzeJavaScript(
                            responseBody,
                            requestResponse.request().url()
                        );
                        
                        addResultsToTable(results);
                    }
                }
                
                progressBar.setValue((i + 1) * 100 / totalMessages);
            }
        } catch (Exception e) {
            api.logging().logToError("Error scanning messages: " + e.getMessage());
        }
    }

    private boolean isJavaScript(String content, var requestResponse) {
        try {
            var response = requestResponse.response();
            String contentType = "";
            
            for (var header : response.headers()) {
                if (header.name().equalsIgnoreCase("Content-Type")) {
                    contentType = header.value();
                    break;
                }
            }
            
            return contentType.contains("javascript") || 
                   contentType.contains("text/plain") ||
                   content.contains("function ") || 
                   content.contains("const ") ||
                   content.contains("let ") ||
                   content.contains("var ");
        } catch (Exception e) {
            return false;
        }
    }

    private void addResultsToTable(ScanResults results) {
        addFindingsToTable(results.getSecretFindings(), "CRITICAL", results.getSourceUrl());
        addFindingsToTable(results.getEndpointFindings(), "HIGH", results.getSourceUrl());
        addFindingsToTable(results.getHardcodedFindings(), "MEDIUM", results.getSourceUrl());
        addFindingsToTable(results.getSuspiciousFindings(), "MEDIUM", results.getSourceUrl());
        addFindingsToTable(results.getFrameworkFindings(), "INFO", results.getSourceUrl());
    }

    private void addFindingsToTable(java.util.List<FindingDetail> findings, 
                                    String severity, String source) {
        for (FindingDetail finding : findings) {
            tableModel.addRow(new Object[]{
                severity,
                finding.getType(),
                finding.getMatch(),
                finding.getLineNumber(),
                source
            });
        }
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        detailsArea.setText("Select a finding to view details...");
    }

    private void applyDefaultScanSettings() {
        extensionState.setAutoScan(true);
        extensionState.setScanPassiveOnly(false);
    }
}

class JSplitPane extends javax.swing.JSplitPane {
    public JSplitPane(int orientation, java.awt.Component leftComponent, 
                     java.awt.Component rightComponent) {
        super(orientation, leftComponent, rightComponent);
    }
}
