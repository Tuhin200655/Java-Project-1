package com.dpi.parser;

import com.dpi.pcap.RawPacket;

public class PacketParser {
    public static class ParsedPacket {
        public long timestampSec;
        public long timestampUsec;

        public String srcMac;
        public String destMac;
        public int etherType;

        public boolean hasIp = false;
        public int ipVersion;
        public String srcIp;
        public String destIp;
        public int protocol; // 6=TCP, 17=UDP, 1=ICMP
        public int ttl;

        public boolean hasTcp = false;
        public boolean hasUdp = false;
        public int srcPort;
        public int destPort;

        public int tcpFlags;
        public long seqNumber;
        public long ackNumber;

        public int payloadOffset;
        public int payloadLength;
    }

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    public static ParsedPacket parse(RawPacket raw) {
        if (raw == null || raw.data == null) return null;

        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int offset = 0;

        // 1. Ethernet Header (14 bytes)
        if (len < 14) return null;
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = readUint16BE(data, 12);
        offset = 14;

        // 2. IPv4 Header
        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (len < offset + 20) return null;

            int versionIhl = data[offset] & 0xFF;
            parsed.ipVersion = (versionIhl >> 4) & 0x0F;
            if (parsed.ipVersion != 4) return null;

            int ihl = versionIhl & 0x0F;
            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || len < offset + ipHeaderLen) return null;

            parsed.ttl = data[offset + 8] & 0xFF;
            parsed.protocol = data[offset + 9] & 0xFF;

            parsed.srcIp = (data[offset + 12] & 0xFF) + "." +
                           (data[offset + 13] & 0xFF) + "." +
                           (data[offset + 14] & 0xFF) + "." +
                           (data[offset + 15] & 0xFF);

            parsed.destIp = (data[offset + 16] & 0xFF) + "." +
                            (data[offset + 17] & 0xFF) + "." +
                            (data[offset + 18] & 0xFF) + "." +
                            (data[offset + 19] & 0xFF);

            parsed.hasIp = true;
            offset += ipHeaderLen;

            // 3. Transport Layer
            if (parsed.protocol == PROTOCOL_TCP) {
                if (len < offset + 20) return null;

                parsed.srcPort = readUint16BE(data, offset);
                parsed.destPort = readUint16BE(data, offset + 2);
                parsed.seqNumber = readUint32BE(data, offset + 4);
                parsed.ackNumber = readUint32BE(data, offset + 8);

                int dataOffset = (data[offset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = dataOffset * 4;
                parsed.tcpFlags = data[offset + 13] & 0xFF;

                if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) return null;
                parsed.hasTcp = true;
                offset += tcpHeaderLen;

            } else if (parsed.protocol == PROTOCOL_UDP) {
                if (len < offset + 8) return null;

                parsed.srcPort = readUint16BE(data, offset);
                parsed.destPort = readUint16BE(data, offset + 2);
                parsed.hasUdp = true;
                offset += 8;
            }
        }

        if (offset < len) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = len - offset;
        } else {
            parsed.payloadOffset = len;
            parsed.payloadLength = 0;
        }

        return parsed;
    }

    public static String macToString(byte[] data, int off) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[off] & 0xFF, data[off + 1] & 0xFF, data[off + 2] & 0xFF,
            data[off + 3] & 0xFF, data[off + 4] & 0xFF, data[off + 5] & 0xFF);
    }

    public static int readUint16BE(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int off) {
        return ((long)(data[off] & 0xFF) << 24) |
               ((long)(data[off + 1] & 0xFF) << 16) |
               ((long)(data[off + 2] & 0xFF) << 8) |
               ((long)(data[off + 3] & 0xFF));
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x02) != 0) sb.append("SYN ");
        if ((flags & 0x10) != 0) sb.append("ACK ");
        if ((flags & 0x01) != 0) sb.append("FIN ");
        if ((flags & 0x04) != 0) sb.append("RST ");
        if ((flags & 0x08) != 0) sb.append("PSH ");
        if ((flags & 0x20) != 0) sb.append("URG ");
        return sb.length() > 0 ? sb.toString().trim() : "none";
    }
}

