package com.dpi;

import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("packet-analyzer");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        int numLbs = 2;
        int fpsPerLb = 2;
        boolean verbose = false;
        String rulesFile = "";

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if ("--block-ip".equals(arg) && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if ("--block-app".equals(arg) && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if ("--block-domain".equals(arg) && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if ("--rules".equals(arg) && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if ("--lbs".equals(arg) && i + 1 < args.length) {
                numLbs = Integer.parseInt(args[++i]);
            } else if ("--fps".equals(arg) && i + 1 < args.length) {
                fpsPerLb = Integer.parseInt(args[++i]);
            } else if ("--verbose".equals(arg)) {
                verbose = true;
            } else if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage("packet-analyzer");
                System.exit(0);
            }
        }

        DpiEngine.Config config = new DpiEngine.Config(numLbs, fpsPerLb, 10000, rulesFile, verbose);
        DpiEngine engine = new DpiEngine(config);

        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }

        if (!rulesFile.isEmpty()) {
            engine.loadRules(rulesFile);
        }

        for (String ip : blockIps) {
            engine.blockIP(ip);
        }

        for (String app : blockApps) {
            engine.blockApp(app);
        }

        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }

        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            System.exit(1);
        }

        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }

    private static void printUsage(String program) {
        System.out.println("""
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                           ║
║               Deep Packet Inspection System                  ║
╚══════════════════════════════════════════════════════════════╝

Usage: java -jar %s.jar <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  java -jar packet-analyzer.jar capture.pcap filtered.pcap
  java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app YouTube
  java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  java -jar packet-analyzer.jar capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub
""".formatted(program));
    }
}

