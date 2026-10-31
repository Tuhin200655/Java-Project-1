package com.dpi.inspector;

import java.util.Optional;

public class DnsExtractor {
    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // Check QR bit (byte 2, bit 7) - 0 = query, 1 = response
        if ((payload[offset + 2] & 0x80) != 0) return false;
        // Check QDCOUNT > 0 (bytes 4-5)
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount > 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = offset + 12;
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLen = payload[pos] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break; // Compression pointer or invalid

            pos++;
            if (pos + labelLen > end) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        return domain.length() > 0 ? Optional.of(domain.toString()) : Optional.empty();
    }
}

