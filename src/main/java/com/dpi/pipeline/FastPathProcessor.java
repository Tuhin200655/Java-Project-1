package com.dpi.pipeline;

import com.dpi.inspector.DnsExtractor;
import com.dpi.inspector.HttpHostExtractor;
import com.dpi.inspector.SniExtractor;
import com.dpi.model.*;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.util.AppClassifier;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

public class FastPathProcessor implements Runnable {
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private volatile boolean running = false;
    private Thread thread;

    private final AtomicLong processed = new AtomicLong(0);
    private final AtomicLong forwarded = new AtomicLong(0);
    private final AtomicLong dropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    public FastPathProcessor(int fpId, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this, "FP-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join(2000);
            } catch (InterruptedException ignored) {}
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + processed.get() + " packets)");
    }

    @Override
    public void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.popWithTimeout(100);
                if (job == null) {
                    connTracker.cleanupStale(Duration.ofSeconds(300));
                    continue;
                }

                processed.incrementAndGet();
                PacketAction action = processPacket(job);

                if (outputCallback != null) {
                    outputCallback.accept(job, action);
                }

                if (action == PacketAction.DROP) {
                    dropped.incrementAndGet();
                } else {
                    forwarded.incrementAndGet();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreate(job.tuple);
        connTracker.update(conn, job.data.length, true);

        if (job.tuple.protocol == 6) {
            updateTcpState(conn, job.tcpFlags);
        }

        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) return;

        byte[] data = job.data;
        int offset = job.payloadOffset;
        int length = job.payloadLength;

        // Try TLS SNI extraction
        if (job.tuple.dstPort == 443 || length >= 50) {
            Optional<String> sni = SniExtractor.extract(data, offset, length);
            if (sni.isPresent()) {
                sniExtractions.incrementAndGet();
                AppType app = AppClassifier.sniToAppType(sni.get());
                connTracker.classify(conn, app, sni.get());
                if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                    classificationHits.incrementAndGet();
                }
                return;
            }
        }

        // Try HTTP Host
        if (job.tuple.dstPort == 80) {
            Optional<String> host = HttpHostExtractor.extract(data, offset, length);
            if (host.isPresent()) {
                AppType app = AppClassifier.sniToAppType(host.get());
                connTracker.classify(conn, app, host.get());
                if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                    classificationHits.incrementAndGet();
                }
                return;
            }
        }

        // DNS query inspection
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = DnsExtractor.extractQuery(data, offset, length);
            if (domain.isPresent()) {
                connTracker.classify(conn, AppType.DNS, domain.get());
                return;
            }
        }

        // Port-based fallback
        if (job.tuple.dstPort == 80) {
            connTracker.classify(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classify(conn, AppType.HTTPS, "");
        }
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) return PacketAction.FORWARD;

        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
            job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (reason.isPresent()) {
            RuleManager.BlockReason r = reason.get();
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + r.type() + " " + r.detail());
            connTracker.block(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTcpState(Connection conn, int flags) {
        int SYN = 0x02;
        int ACK = 0x10;
        int FIN = 0x01;
        int RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }

        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((flags & FIN) != 0) {
            conn.finSeen = true;
        }

        if ((flags & RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.finSeen && (flags & ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() { return inputQueue; }
    public ConnectionTracker getConnectionTracker() { return connTracker; }
    public int getId() { return fpId; }

    public record FPStats(long processed, long forwarded, long dropped, long connections, long sniExtractions, long classificationHits) {}

    public FPStats getStats() {
        return new FPStats(processed.get(), forwarded.get(), dropped.get(),
            connTracker.getActiveCount(), sniExtractions.get(), classificationHits.get());
    }
}

