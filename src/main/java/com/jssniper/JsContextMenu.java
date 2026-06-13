package com.jssniper;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Right-click actions, all delegating to {@link ScanRunner} and showing results
 * in the JSsniper > Results tab:
 *   - "JSsniper: Scan the host"
 *   - "JSsniper: Scan specific response"
 *   - "JSsniper: Dump static files"
 */
public class JsContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ScanRunner runner;
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "jssniper-scan");
                t.setDaemon(true);
                return t;
            });

    public JsContextMenu(MontoyaApi api, ScanRunner runner) {
        this.api = api;
        this.runner = runner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        if (selected.isEmpty()) {
            event.messageEditorRequestResponse()
                    .ifPresent(editor -> selected.add(editor.requestResponse()));
        }
        if (selected.isEmpty()) {
            return null;
        }

        Set<String> hosts = new LinkedHashSet<>();
        for (HttpRequestResponse rr : selected) {
            try {
                hosts.add(rr.httpService().host());
            } catch (Exception ignored) {
                // skip entries without a service
            }
        }

        List<Component> items = new ArrayList<>();

        JMenuItem hostScan = new JMenuItem("JSsniper: Scan the host");
        hostScan.addActionListener(e -> executor.submit(() -> runner.scanHosts(hosts)));
        items.add(hostScan);

        JMenuItem responseScan = new JMenuItem("JSsniper: Scan specific response");
        responseScan.addActionListener(e -> executor.submit(() -> runner.scanSelected(selected)));
        items.add(responseScan);

        JMenuItem dump = new JMenuItem("JSsniper: Dump static files");
        dump.addActionListener(e -> executor.submit(() -> runner.dumpStatic(hosts)));
        items.add(dump);

        return items;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
