package com.dpi.inspector;

import java.util.Optional;

public class HttpHostExtractor {
    private static final String[] HTTP_METHODS = {
        "GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"
    };

    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        String start = new String(payload, offset, 4);
        for (String m : HTTP_METHODS) {
            if (m.equals(start)) return true;
        }
        return false;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                payload[i + 4] == ':') {

                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                int e = start;
                while (e < end && payload[e] != '\r' && payload[e] != '\n') {
                    e++;
                }

                if (e > start) {
                    String host = new String(payload, start, e - start);
                    int colon = host.indexOf(':');
                    if (colon >= 0) {
                        host = host.substring(0, colon);
                    }
                    return Optional.of(host.trim());
                }
            }
        }

        return Optional.empty();
    }
}

