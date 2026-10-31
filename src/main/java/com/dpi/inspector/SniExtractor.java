package com.dpi.inspector;

import java.util.Optional;

public class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;

        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;

        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        int pos = offset + 5; // Skip TLS record header

        // Handshake header
        pos += 4; // Skip Handshake Type (1) + Handshake Length (3)

        // Client Version
        pos += 2;

        // Random (32 bytes)
        pos += 32;

        // Session ID
        if (pos >= end) return Optional.empty();
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher Suites
        if (pos + 2 > end) return Optional.empty();
        int cipherLen = readUint16BE(payload, pos);
        pos += 2 + cipherLen;

        // Compression Methods
        if (pos >= end) return Optional.empty();
        int compLen = payload[pos] & 0xFF;
        pos += 1 + compLen;

        // Extensions
        if (pos + 2 > end) return Optional.empty();
        int extLen = readUint16BE(payload, pos);
        pos += 2;

        int extEnd = Math.min(pos + extLen, end);

        while (pos + 4 <= extEnd) {
            int extType = readUint16BE(payload, pos);
            int extDataLen = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extDataLen > extEnd) break;

            if (extType == EXTENSION_SNI) {
                if (extDataLen < 5) break;

                int sniListLen = readUint16BE(payload, pos);
                if (sniListLen < 3) break;

                int sniType = payload[pos + 2] & 0xFF;
                int sniLen = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLen > extDataLen - 5) break;

                return Optional.of(new String(payload, pos + 5, sniLen));
            }

            pos += extDataLen;
        }

        return Optional.empty();
    }

    private static int readUint16BE(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }
}

