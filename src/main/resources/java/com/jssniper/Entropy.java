package com.jssniper;

/** Shannon entropy helper, used to filter low-entropy false positives. */
public final class Entropy {

    private Entropy() { }

    public static double shannon(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        int[] freq = new int[128];
        int len = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                freq[c]++;
                len++;
            }
        }
        if (len == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}
