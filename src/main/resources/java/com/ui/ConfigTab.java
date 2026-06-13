package com.jssniper.ui;

import com.jssniper.Category;
import com.jssniper.ScanConfig;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;

/**
 * Configuration tab shown under the "JSsniper" suite tab. Toggles update the
 * shared {@link ScanConfig}, which the scanner reads on its own threads.
 */
public class ConfigTab {

    private final JPanel panel;

    public ConfigTab(ScanConfig config) {
        panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        JLabel header = new JLabel("JSsniper \u2014 passive JavaScript secret/endpoint scanner");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 15f));

        JPanel options = new JPanel();
        options.setLayout(new BoxLayout(options, BoxLayout.Y_AXIS));
        options.setBorder(BorderFactory.createTitledBorder("Detection categories"));

        for (Category category : Category.values()) {
            JCheckBox cb = new JCheckBox(
                    category.title() + "   [" + category.severity() + "]",
                    config.isEnabled(category));
            cb.addActionListener(e -> config.setEnabled(category, cb.isSelected()));
            options.add(cb);
        }

        options.add(new JSeparator());

        JCheckBox inline = new JCheckBox(
                "Also scan inline <script> blocks in HTML pages", config.scanInlineHtml());
        inline.addActionListener(e -> config.setScanInlineHtml(inline.isSelected()));

        JCheckBox scope = new JCheckBox(
                "Only scan in-scope items", config.inScopeOnly());
        scope.addActionListener(e -> config.setInScopeOnly(scope.isSelected()));

        options.add(inline);
        options.add(scope);

        JTextArea about = new JTextArea(
                "Passive: findings appear under Dashboard and Target > Issues as you browse.\n"
                        + "Whole host: right-click a host > 'JSsniper: scan ALL JavaScript on this host'.\n"
                        + "On demand: right-click any item > 'JSsniper: scan selected response(s)'.\n\n"
                        + "Detection is pattern/heuristic based \u2014 treat results as leads and verify manually.");
        about.setEditable(false);
        about.setOpaque(false);
        about.setBorder(BorderFactory.createTitledBorder("About"));

        JPanel north = new JPanel(new BorderLayout(0, 10));
        north.add(header, BorderLayout.NORTH);
        north.add(options, BorderLayout.CENTER);
        north.add(about, BorderLayout.SOUTH);

        panel.add(north, BorderLayout.NORTH);
    }

    public Component component() {
        return panel;
    }
}
