package com.jssniper;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Runtime configuration shared between the UI (Event Dispatch Thread) and the
 * scanner (Burp audit threads). All fields are safe for concurrent access.
 */
public class ScanConfig {

    private final Set<Category> enabled = new CopyOnWriteArraySet<>();
    private volatile boolean scanInlineHtml = true;
    private volatile boolean inScopeOnly = false;

    public ScanConfig() {
        for (Category c : Category.values()) {
            if (c.defaultOn()) {
                enabled.add(c);
            }
        }
    }

    public boolean isEnabled(Category c) {
        return enabled.contains(c);
    }

    public void setEnabled(Category c, boolean on) {
        if (on) {
            enabled.add(c);
        } else {
            enabled.remove(c);
        }
    }

    public boolean scanInlineHtml() { return scanInlineHtml; }
    public void setScanInlineHtml(boolean v) { this.scanInlineHtml = v; }

    public boolean inScopeOnly() { return inScopeOnly; }
    public void setInScopeOnly(boolean v) { this.inScopeOnly = v; }
}
