package com.dpi.pipeline;

import com.dpi.model.AppType;
import com.dpi.model.PacketAction;
import com.dpi.model.PacketJob;
import com.dpi.rules.RuleManager;

import java.util.*;
import java.util.function.BiConsumer;

public class FpManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FpManager(int numFps, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        fps.forEach(FastPathProcessor::start);
    }

    public void stopAll() {
        fps.forEach(FastPathProcessor::stop);
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public List<ThreadSafeQueue<PacketJob>> getQueues() {
        return fps.stream().map(FastPathProcessor::getInputQueue).toList();
    }

    public int getNumFPs() {
        return fps.size();
    }

    public record AggregatedStats(long totalProcessed, long totalForwarded, long totalDropped, long totalConnections) {}

    public AggregatedStats getAggregatedStats() {
        long p = 0, f = 0, d = 0, c = 0;
        for (FastPathProcessor fp : fps) {
            var s = fp.getStats();
            p += s.processed();
            f += s.forwarded();
            d += s.dropped();
            c += s.connections();
        }
        return new AggregatedStats(p, f, d, c);
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
            });
        }

        long total = appCounts.values().stream().mapToLong(Long::longValue).sum();
        long totalClassified = appCounts.entrySet().stream()
            .filter(e -> e.getKey() != AppType.UNKNOWN)
            .mapToLong(Map.Entry::getValue)
            .sum();
        long totalUnknown = total - totalClassified;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

        sb.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        sb.append(String.format("║ Classified:           %10d (%5.1f%%)                  ║%n", totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%5.1f%%)                  ║%n", totalUnknown, unknownPct));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        long finalTotal = total;
        appCounts.entrySet().stream()
            .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
            .forEach(e -> {
                double pct = finalTotal > 0 ? (100.0 * e.getValue() / finalTotal) : 0;
                int barLen = (int) (pct / 5);
                String bar = "#".repeat(Math.max(0, barLen));
                sb.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    e.getKey().displayName(), e.getValue(), pct, bar));
            });

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}

