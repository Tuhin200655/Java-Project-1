package com.dpi.model;

public class FiveTuple {
    public final long srcIp;   // uint32 stored as unsigned long
    public final long dstIp;
    public final int srcPort;  // uint16 stored as int
    public final int dstPort;
    public final int protocol; // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp &&
               dstIp == t.dstIp &&
               srcPort == t.srcPort &&
               dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Faithful reproduction of C++ FiveTupleHash
        long h = 0;
        h ^= Long.hashCode(srcIp) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Long.hashCode(dstIp) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort) + 0x9e3779b9L + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
        return (int) h;
    }

    public static String toIpString(long ip) {
        return (ip & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    @Override
    public String toString() {
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return toIpString(srcIp) + ":" + srcPort + " -> " +
               toIpString(dstIp) + ":" + dstPort + " (" + protoStr + ")";
    }
}

