package com.dpi.tracker;

import com.dpi.model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreate(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection get(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        return connections.get(tuple.reverse());
    }

    public void update(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classify(Connection conn, AppType app, String sni) {
        if (conn == null || conn.state == ConnectionState.CLASSIFIED) return;
        conn.appType = app;
        conn.sni = sni != null ? sni : "";
        conn.state = ConnectionState.CLASSIFIED;
        classifiedCount++;
    }

    public void block(Connection conn) {
        if (conn == null) return;
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void close(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection c = it.next().getValue();
            if (c.lastSeen.isBefore(cutoff) || c.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public void forEach(Consumer<Connection> action) {
        connections.values().forEach(action);
    }

    public int getActiveCount() {
        return connections.size();
    }

    public record TrackerStats(int activeConnections, long totalSeen, long classified, long blocked) {}

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() {
        connections.clear();
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        connections.entrySet().stream()
            .min(Comparator.comparing(e -> e.getValue().lastSeen))
            .map(Map.Entry::getKey)
            .ifPresent(connections::remove);
    }
}

