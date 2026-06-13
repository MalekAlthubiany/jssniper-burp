package com.jssniper.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.jssniper.ResultsStore;
import com.jssniper.ScanRunner;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The JSsniper "Results" tab: a modern, colour-coded findings table with a
 * severity summary, an HTML advisory pane and embedded Burp request/response
 * editors that highlight the matched (vulnerable) bytes. Works in Burp Community
 * Edition — it does not rely on Burp's scanner or Issues panel.
 */
public class ResultsTab {

    private static final String[] COLUMNS = {"Severity", "Confidence", "Issue", "Host", "Path"};
    private static final Color BG = new Color(247, 248, 250);
    private static final Color CARD = Color.WHITE;
    private static final Color LINE = new Color(225, 228, 232);

    private final ResultsStore store;
    private final ScanRunner runner;
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "jssniper-results-scan");
                t.setDaemon(true);
                return t;
            });

    private final JPanel panel = new JPanel(new BorderLayout());
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final JEditorPane advisory = new JEditorPane("text/html", "");
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final Chip chipHigh = new Chip("High", new Color(0xC0, 0x39, 0x2B));
    private final Chip chipMed = new Chip("Medium", new Color(0xE0, 0x7B, 0x1A));
    private final Chip chipLow = new Chip("Low", new Color(0xC9, 0xA2, 0x27));
    private final Chip chipInfo = new Chip("Info", new Color(0x2D, 0x74, 0xB5));
    private final JLabel total = new JLabel("0 findings");

    private List<ResultsStore.Row> view = new ArrayList<>();

    public ResultsTab(ResultsStore store, ScanRunner runner, MontoyaApi api) {
        this.store = store;
        this.runner = runner;
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        build();
        store.setListener(this::refresh);
    }

    private void build() {
        panel.setBackground(BG);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(buildHeader(), BorderLayout.NORTH);

        configureTable();
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createLineBorder(LINE));

        advisory.setEditable(false);
        advisory.setText(placeholder());
        JScrollPane advScroll = new JScrollPane(advisory);
        advScroll.setBorder(null);

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Advisory", advScroll);
        detailTabs.addTab("Request", requestEditor.uiComponent());
        detailTabs.addTab("Response", responseEditor.uiComponent());
        detailTabs.setBorder(BorderFactory.createLineBorder(LINE));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        split.setBorder(null);
        split.setResizeWeight(0.5);
        split.setDividerSize(8);

        panel.add(split, BorderLayout.CENTER);
    }

    private JPanel buildHeader() {
        JLabel title = new JLabel("JSsniper");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        JLabel subtitle = new JLabel("JavaScript & JSON security findings");
        subtitle.setForeground(new Color(0x6B, 0x72, 0x80));
        subtitle.setFont(subtitle.getFont().deriveFont(12f));

        JPanel titleBox = new JPanel();
        titleBox.setOpaque(false);
        titleBox.setLayout(new javax.swing.BoxLayout(titleBox, javax.swing.BoxLayout.Y_AXIS));
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleBox.add(title);
        titleBox.add(subtitle);

        JPanel chips = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        chips.setOpaque(false);
        chips.add(chipHigh);
        chips.add(chipMed);
        chips.add(chipLow);
        chips.add(chipInfo);

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        top.add(titleBox, BorderLayout.WEST);
        top.add(chips, BorderLayout.EAST);

        // toolbar
        JButton scanAll = new JButton("Scan entire site map");
        scanAll.addActionListener(e -> {
            scanAll.setEnabled(false);
            scanAll.setText("Scanning…");
            executor.submit(() -> {
                try {
                    runner.scanEntireSiteMap();
                } finally {
                    SwingUtilities.invokeLater(() -> {
                        scanAll.setEnabled(true);
                        scanAll.setText("Scan entire site map");
                    });
                }
            });
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> store.clear());

        JComboBox<String> sevFilter = new JComboBox<>(
                new String[]{"All severities", "HIGH", "MEDIUM", "LOW", "INFORMATION"});
        sevFilter.addActionListener(e -> applyFilters());
        this.sevFilter = sevFilter;

        JTextField search = new JTextField(16);
        search.putClientProperty("JTextField.placeholderText", "filter…");
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        this.searchField = search;

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        toolbar.setOpaque(false);
        toolbar.add(scanAll);
        toolbar.add(clear);
        toolbar.add(new JLabel("Severity:"));
        toolbar.add(sevFilter);
        toolbar.add(new JLabel("Search:"));
        toolbar.add(search);
        toolbar.add(Box.createHorizontalStrut(12));
        total.setForeground(new Color(0x37, 0x40, 0x4C));
        toolbar.add(total);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(CARD);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(LINE),
                BorderFactory.createEmptyBorder(10, 12, 4, 12)));
        header.add(top, BorderLayout.NORTH);
        header.add(toolbar, BorderLayout.SOUTH);

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setOpaque(false);
        wrap.add(header, BorderLayout.CENTER);
        wrap.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        return wrap;
    }

    private JComboBox<String> sevFilter;
    private JTextField searchField;

    private void configureTable() {
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);
        table.setRowHeight(24);
        table.setShowGrid(true);
        table.setGridColor(new Color(0xEC, 0xEE, 0xF1));
        table.setIntercellSpacing(new Dimension(0, 0));
        table.getTableHeader().setFont(table.getTableHeader().getFont().deriveFont(Font.BOLD));
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        SeverityRenderer renderer = new SeverityRenderer();
        for (int c = 0; c < COLUMNS.length; c++) {
            table.getColumnModel().getColumn(c).setCellRenderer(renderer);
        }
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(280);
        table.getColumnModel().getColumn(3).setPreferredWidth(180);
        table.getColumnModel().getColumn(4).setPreferredWidth(280);

        TableRowSorter<Model> sorter = new TableRowSorter<>(model);
        sorter.setComparator(0, Comparator.comparingInt(ResultsTab::rank));
        table.setRowSorter(sorter);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showDetail();
            }
        });
    }

    @SuppressWarnings("unchecked")
    private void applyFilters() {
        TableRowSorter<Model> sorter = (TableRowSorter<Model>) table.getRowSorter();
        List<RowFilter<Object, Object>> filters = new ArrayList<>();
        String sev = sevFilter != null ? (String) sevFilter.getSelectedItem() : null;
        if (sev != null && !sev.startsWith("All")) {
            filters.add(RowFilter.regexFilter("^" + sev + "$", 0));
        }
        String q = searchField != null ? searchField.getText().trim() : "";
        if (!q.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(q), 2, 3, 4));
        }
        sorter.setRowFilter(filters.isEmpty() ? null : RowFilter.andFilter(filters));
    }

    private void refresh() {
        view = store.snapshot();
        model.fireTableDataChanged();
        int h = 0, m = 0, l = 0, i = 0;
        for (ResultsStore.Row r : view) {
            switch (r.severity()) {
                case "HIGH" -> h++;
                case "MEDIUM" -> m++;
                case "LOW" -> l++;
                default -> i++;
            }
        }
        chipHigh.setCount(h);
        chipMed.setCount(m);
        chipLow.setCount(l);
        chipInfo.setCount(i);
        total.setText(view.size() + " findings");
    }

    private void showDetail() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            advisory.setText(placeholder());
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= view.size()) {
            return;
        }
        ResultsStore.Row r = view.get(modelRow);
        advisory.setText("<html><body style='font-family:sans-serif;font-size:11px;margin:8px'>"
                + "<h2 style='margin:0 0 6px 0'>" + esc(r.issue()) + "</h2>"
                + "<p style='margin:0 0 8px 0'><b>Severity:</b> <span style='color:" + cssColor(r.severity())
                + "'><b>" + r.severity() + "</b></span> &nbsp;&nbsp; <b>Confidence:</b> " + r.confidence() + "</p>"
                + "<p style='margin:0 0 8px 0;color:#444'><b>URL:</b> " + esc(r.url()) + "</p>"
                + "<div>" + nz(r.detailHtml()) + "</div>"
                + (r.remediation() != null && !r.remediation().isBlank()
                    ? "<hr><div><b>Remediation:</b> " + esc(r.remediation()) + "</div>" : "")
                + "</body></html>");
        advisory.setCaretPosition(0);

        // Populate the embedded request/response editors and highlight evidence.
        if (r.rr() != null) {
            try {
                if (r.rr().request() != null) {
                    requestEditor.setRequest(r.rr().request());
                }
                if (r.rr().response() != null) {
                    responseEditor.setResponse(r.rr().response());
                    if (r.evidence() != null && !r.evidence().isEmpty()) {
                        responseEditor.setSearchExpression(r.evidence().get(0));
                    }
                }
            } catch (Exception ignored) {
                // editor may reject an unusual message; ignore
            }
        }
    }

    public Component component() {
        return panel;
    }

    private static int rank(String severity) {
        return switch (severity) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            case "LOW" -> 2;
            default -> 3;
        };
    }

    private static Color rowColor(String severity) {
        return switch (severity) {
            case "HIGH" -> new Color(0xFC, 0xE4, 0xE2);
            case "MEDIUM" -> new Color(0xFD, 0xEC, 0xD8);
            case "LOW" -> new Color(0xFB, 0xF3, 0xD2);
            default -> new Color(0xE2, 0xED, 0xF7);
        };
    }

    private static String cssColor(String severity) {
        return switch (severity) {
            case "HIGH" -> "#b0281f";
            case "MEDIUM" -> "#b35900";
            case "LOW" -> "#8a7100";
            default -> "#1c5d99";
        };
    }

    private static String placeholder() {
        return "<html><body style='font-family:sans-serif;font-size:11px;margin:10px;color:#555'>"
                + "<p>Select a finding to view its advisory, request and response.</p>"
                + "<p>To populate results: click <b>Scan entire site map</b>, or right-click a host in "
                + "the site map and choose <b>JSsniper: Scan the host</b>.</p></body></html>";
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Rounded severity-count chip. */
    private static class Chip extends JLabel {
        private static final long serialVersionUID = 1L;
        private final Color color;
        private final String label;

        Chip(String label, Color color) {
            super(label + ": 0", SwingConstants.CENTER);
            this.label = label;
            this.color = color;
            setOpaque(false);
            setForeground(Color.WHITE);
            setFont(getFont().deriveFont(Font.BOLD, 11f));
            setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 10));
        }

        void setCount(int n) {
            setText(label + ": " + n);
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    private class Model extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        @Override public int getRowCount() { return view.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int c) { return COLUMNS[c]; }
        @Override
        public Object getValueAt(int row, int col) {
            ResultsStore.Row r = view.get(row);
            return switch (col) {
                case 0 -> r.severity();
                case 1 -> r.confidence();
                case 2 -> r.issue();
                case 3 -> r.host();
                default -> r.path();
            };
        }
    }

    private class SeverityRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean selected,
                                                       boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, column);
            int modelRow = t.convertRowIndexToModel(row);
            String severity = (modelRow >= 0 && modelRow < view.size())
                    ? view.get(modelRow).severity() : "INFORMATION";
            Color base = rowColor(severity);
            c.setBackground(selected ? base.darker() : base);
            c.setForeground(column == 0 ? deriveText(severity) : Color.BLACK);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            if (column == 0) {
                c.setFont(c.getFont().deriveFont(Font.BOLD));
            }
            return c;
        }

        private Color deriveText(String severity) {
            return switch (severity) {
                case "HIGH" -> new Color(0x90, 0x20, 0x18);
                case "MEDIUM" -> new Color(0x8A, 0x45, 0x00);
                case "LOW" -> new Color(0x6E, 0x5A, 0x00);
                default -> new Color(0x16, 0x4A, 0x7A);
            };
        }
    }
}
