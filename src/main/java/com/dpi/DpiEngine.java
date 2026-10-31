package com.dpi;

import com.dpi.model.*;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.*;
import com.dpi.pipeline.*;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.GlobalConnectionTable;

import java.io.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class DpiEngine {
    public record Config(int numLoadBalancers, int fpsPerLb, int queueSize, String rulesFile, boolean verbose) {
        public Config() {
            this(2, 2, 10000, "", false);
        }
    }

    private final Config config;
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;
    private FpManager fpManager;
    private LbManager lbManager;

    private final ThreadSafeQueue<PacketJob> outputQueue = new ThreadSafeQueue<>(10000);
    private Thread outputThread;
    private OutputStream outputStream;
    private final Object outputLock = new Object();

    private final DpiStats stats = new DpiStats();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread readerThread;

    public DpiEngine(Config config) {
        this.config = config;
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.printf ("║   Load Balancers:    %3d                                       ║%n", config.numLoadBalancers());
        System.out.printf ("║   FPs per LB:        %3d                                       ║%n", config.fpsPerLb());
        System.out.printf ("║   Total FP threads:  %3d                                       ║%n", config.numLoadBalancers() * config.fpsPerLb());
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (config.rulesFile() != null && !config.rulesFile().isEmpty()) {
            ruleManager.loadRules(config.rulesFile());
        }

        int totalFps = config.numLoadBalancers() * config.fpsPerLb();

        fpManager = new FpManager(totalFps, ruleManager, this::handleOutput);

        List<ThreadSafeQueue<PacketJob>> fpQueues = fpManager.getQueues();
        lbManager = new LbManager(config.numLoadBalancers(), config.fpsPerLb(), fpQueues);

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.start();

        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);

        if (lbManager != null) lbManager.stopAll();
        if (fpManager != null) fpManager.stopAll();

        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join(3000);
            } catch (InterruptedException ignored) {}
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            outputStream = new BufferedOutputStream(fos);

            start();

            readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
            readerThread.start();

            try {
                readerThread.join();
            } catch (InterruptedException ignored) {}

            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {}

            stop();

            outputStream.flush();

        } catch (IOException e) {
            System.err.println("[DPIEngine] IO Error: " + e.getMessage());
            return false;
        }

        System.out.println(generateReport());
        System.out.println(fpManager.generateClassificationReport());

        return true;
    }

    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file");
                return;
            }

            synchronized (outputLock) {
                PcapReader.writeGlobalHeader(outputStream, reader.getGlobalHeader());
            }

            System.out.println("[Reader] Starting packet processing...");
            int packetId = 0;
            RawPacket raw;

            while ((raw = reader.readNextPacket()) != null) {
                PacketParser.ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null || !parsed.hasIp) continue;
                if (!parsed.hasTcp && !parsed.hasUdp) continue;

                PacketJob job = createPacketJob(raw, parsed, packetId++);

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) {
                    stats.tcpPackets.incrementAndGet();
                } else {
                    stats.udpPackets.incrementAndGet();
                }

                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                try {
                    lb.getInputQueue().push(job);
                } catch (InterruptedException e) {
                    break;
                }
            }

            System.out.println("[Reader] Finished reading " + packetId + " packets");

        } catch (IOException e) {
            System.err.println("[Reader] Error: " + e.getMessage());
        }
    }

    private PacketJob createPacketJob(RawPacket raw, PacketParser.ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;
        job.data = raw.data;

        job.tuple = new FiveTuple(
            RuleManager.parseIp(parsed.srcIp),
            RuleManager.parseIp(parsed.destIp),
            parsed.srcPort,
            parsed.destPort,
            parsed.protocol
        );

        job.tcpFlags = parsed.tcpFlags;
        job.ethOffset = 0;
        job.ipOffset = 14;

        if (raw.data.length > 14) {
            int ipIhl = raw.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && raw.data.length > job.transportOffset) {
                int tcpDataOffset = (raw.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }

            if (job.payloadOffset < raw.data.length) {
                job.payloadLength = raw.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.popWithTimeout(100);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }

        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.push(job);
        } catch (InterruptedException ignored) {}
    }

    private void writeOutputPacket(PacketJob job) {
        if (outputStream == null) return;
        synchronized (outputLock) {
            try {
                PcapReader.writePacket(outputStream, job.tsSec, job.tsUsec, job.data);
            } catch (IOException e) {
                System.err.println("[OutputWriter] Error writing packet: " + e.getMessage());
            }
        }
    }

    // ========== Rule Management API ==========

    public void blockIP(String ip) {
        if (ruleManager != null) ruleManager.blockIp(ip);
    }

    public void unblockIP(String ip) {
        if (ruleManager != null) ruleManager.unblockIp(ip);
    }

    public void blockApp(String app) {
        if (ruleManager != null) ruleManager.blockApp(app);
    }

    public void blockDomain(String domain) {
        if (ruleManager != null) ruleManager.blockDomain(domain);
    }

    public void unblockDomain(String domain) {
        if (ruleManager != null) ruleManager.unblockDomain(domain);
    }

    public boolean loadRules(String filename) {
        return ruleManager != null && ruleManager.loadRules(filename);
    }

    public boolean saveRules(String filename) {
        return ruleManager != null && ruleManager.saveRules(filename);
    }

    // ========== Reporting ==========

    public String generateReport() {
        StringBuilder ss = new StringBuilder();

        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");

        ss.append("║ PACKET STATISTICS                                             ║\n");
        ss.append(String.format("║   Total Packets:      %12d                        ║%n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                        ║%n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                        ║%n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                        ║%n", stats.udpPackets.get()));

        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                          ║\n");
        ss.append(String.format("║   Forwarded:          %12d                        ║%n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                        ║%n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            ss.append(String.format("║   Drop Rate:          %11.2f%%                        ║%n", dropRate));
        }

        if (lbManager != null) {
            var lbStats = lbManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            ss.append(String.format("║   LB Received:        %12d                        ║%n", lbStats.totalReceived()));
            ss.append(String.format("║   LB Dispatched:      %12d                        ║%n", lbStats.totalDispatched()));
        }

        if (fpManager != null) {
            var fpStats = fpManager.getAggregatedStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ FAST PATH STATISTICS                                          ║\n");
            ss.append(String.format("║   FP Processed:       %12d                        ║%n", fpStats.totalProcessed()));
            ss.append(String.format("║   FP Forwarded:       %12d                        ║%n", fpStats.totalForwarded()));
            ss.append(String.format("║   FP Dropped:         %12d                        ║%n", fpStats.totalDropped()));
            ss.append(String.format("║   Active Connections: %12d                        ║%n", fpStats.totalConnections()));
        }

        if (ruleManager != null) {
            var ruleStats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                                ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                        ║%n", ruleStats.blockedIps()));
            ss.append(String.format("║   Blocked Apps:       %12d                        ║%n", ruleStats.blockedApps()));
            ss.append(String.format("║   Blocked Domains:    %12d                        ║%n", ruleStats.blockedDomains()));
            ss.append(String.format("║   Blocked Ports:      %12d                        ║%n", ruleStats.blockedPorts()));
        }

        ss.append("╚══════════════════════════════════════════════════════════════╝\n");

        return ss.toString();
    }

    public DpiStats getStats() {
        return stats;
    }
}

