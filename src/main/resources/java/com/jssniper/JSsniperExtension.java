package com.jssniper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.jssniper.ui.ConfigTab;
import com.jssniper.ui.ResultsTab;

import javax.swing.JTabbedPane;

/**
 * JSsniper — JavaScript & JSON security analyzer for Burp Suite.
 *
 * Results are shown in the JSsniper suite tab ("Results"), which works in Burp
 * Community Edition (no scanner/Issues panel required). In Professional, findings
 * also appear under Target > Issues.
 *
 * Right-click a host > "JSsniper: Scan the host", or use "Scan entire site map"
 * in the Results tab.
 *
 * Detection seeds from https://github.com/MalekAlthubiany/JSsniper.py
 * For authorized security testing only.
 */
public class JSsniperExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JSsniper");

        ScanConfig config = new ScanConfig();
        PatternStore store = PatternStore.loadDefault(api);
        LibraryCheck libraries = LibraryCheck.loadDefault(api);
        ResultsStore results = new ResultsStore();

        JsScanCheck scanCheck = new JsScanCheck(api, config, store, libraries, results);
        api.scanner().registerPassiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);

        ScanRunner runner = new ScanRunner(api, scanCheck, config, results);

        JsContextMenu contextMenu = new JsContextMenu(api, runner);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        final JTabbedPane[] tabsHolder = new JTabbedPane[1];
        Runnable buildUi = () -> {
            ResultsTab resultsTab = new ResultsTab(results, runner, api);
            ConfigTab configTab = new ConfigTab(config);
            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Results", resultsTab.component());
            tabs.addTab("Settings", configTab.component());
            tabsHolder[0] = tabs;
        };
        try {
            if (javax.swing.SwingUtilities.isEventDispatchThread()) {
                buildUi.run();
            } else {
                javax.swing.SwingUtilities.invokeAndWait(buildUi);
            }
        } catch (Exception e) {
            api.logging().logToError("UI build error: " + e.getMessage());
        }
        api.userInterface().registerSuiteTab("JSsniper", tabsHolder[0]);

        api.extension().registerUnloadingHandler(() -> {
            contextMenu.shutdown();
            api.logging().logToOutput("JSsniper unloaded.");
        });

        api.logging().logToOutput("JSsniper loaded — " + store.size() + " patterns, "
                + libraries.size() + " library checks. Open the JSsniper tab and click "
                + "'Scan entire site map', or right-click a host > 'JSsniper: Scan the host'.");
    }
}
