package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.ui.SwingUtils;
import burp.api.montoya.ui.components.RawEditor;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtension implements BurpExtension {

    private MontoyaApi api;
    private ExtensionState extensionState;
    private ExecutorService executorService;
    private ScannerCore scannerCore;
    private UnloadingHandler unloadingHandler;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.extensionState = new ExtensionState();
        this.executorService = Executors.newFixedThreadPool(4);
        this.scannerCore = new ScannerCore(api, extensionState);
        this.unloadingHandler = new UnloadingHandler(executorService, scannerCore);

        api.extension().setName("JSSniper - JavaScript Security Scanner");
        
        initializeUI();
        registerEventHandlers();
        
        api.logging().logToOutput("JSSniper extension loaded successfully");
    }

    private void initializeUI() {
        try {
            JPanel mainPanel = createMainPanel();
            JSniperTab jsSniperTab = new JSniperTab(api, scannerCore, executorService, extensionState);
            
            api.userInterface().registerSuiteTab("JSSniper", jsSniperTab);
        } catch (Exception e) {
            api.logging().logToError("Failed to initialize UI: " + e.getMessage());
            e.printStackTrace(api.logging().errorStream());
        }
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JLabel titleLabel = new JLabel("JavaScript Security Scanner");
        titleLabel.setFont(titleLabel.getFont().deriveFont(16.0f));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        panel.add(titleLabel, BorderLayout.NORTH);
        return panel;
    }

    private void registerEventHandlers() {
        api.extension().registerUnloadingHandler(unloadingHandler);
        api.http().registerSessionHandlingAction(new ScannerSessionHandler(api, scannerCore));
    }

    public MontoyaApi getApi() {
        return api;
    }

    public ExecutorService getExecutorService() {
        return executorService;
    }

    public ScannerCore getScannerCore() {
        return scannerCore;
    }

    public ExtensionState getExtensionState() {
        return extensionState;
    }
}
