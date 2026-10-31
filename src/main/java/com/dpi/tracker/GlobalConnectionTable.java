package com.dpi.tracker;

import com.dpi.model.AppType;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class GlobalConnectionTable {
    private final ConnectionTracker[] trackers;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        trackers = new ConnectionTracker[numFps];
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId >= 0 && fpId < trackers.length) {
                trackers[fpId] = tracker;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String generateReport() {
        lock.readLock().lock();
        try {
            long totalActive = 0;
            long totalSeen = 0;
            Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker t : trackers) {
                if (t == null) continue;
                var s = t.getStats();
                totalActive += s.activeConnections();
                totalSeen += s.totalSeen();

                t.forEach(conn -> {
                    appDistribution.merge(conn.appType, 1L, Long::sum);
                    if (!conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            StringBuilder sb = new StringBuilder();
            sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
            sb.append("║               CONNECTION STATISTICS REPORT                    ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append(String.format("║ Active Connections:     %10d                          ║%n", totalActive));
            sb.append(String.format("║ Total Connections Seen: %10d                          ║%n", totalSeen));
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");

            long totalApps = appDistribution.values().stream().mapToLong(Long::longValue).sum();

            appDistribution.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .forEach(e -> {
                    double pct = totalApps > 0 ? (100.0 * e.getValue() / totalApps) : 0;
                    sb.append(String.format("║ %-20s %10d (%5.1f%%)           ║%n",
                        e.getKey().displayName(), e.getValue(), pct));
                });

            if (!domainCounts.isEmpty()) {
                sb.append("╠══════════════════════════════════════════════════════════════╣\n");
                sb.append("║                      TOP DOMAINS                             ║\n");
                sb.append("╠══════════════════════════════════════════════════════════════╣\n");

                domainCounts.entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                    .limit(20)
                    .forEach(e -> {
                        String domain = e.getKey();
                        if (domain.length() > 35) {
                            domain = domain.substring(0, 32) + "...";
                        }
                        sb.append(String.format("║ %-40s %10d           ║%n", domain, e.getValue()));
                    });
            }

            sb.append("╚══════════════════════════════════════════════════════════════╝\n");
            return sb.toString();

        } finally {
            lock.readLock().unlock();
        }
    }
}

