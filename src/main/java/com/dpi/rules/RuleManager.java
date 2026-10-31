package com.dpi.rules;

import com.dpi.model.AppType;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {
    public enum BlockType { IP, APP, DOMAIN, PORT }
    public record BlockReason(BlockType type, String detail) {}

    private final ReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Long> blockedIps = new HashSet<>();

    private final ReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<>();

    private final ReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();

    private final ReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    // ========== IP Blocking ==========

    public void blockIp(String ip) {
        blockIp(parseIp(ip));
    }

    public void blockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void unblockIp(String ip) {
        unblockIp(parseIp(ip));
    }

    public void unblockIp(long ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public boolean isIpBlocked(long ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIps() {
        ipLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>();
            for (long ip : blockedIps) {
                list.add(ipToString(ip));
            }
            return list;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ========== Application Blocking ==========

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.displayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public void blockApp(String appName) {
        for (AppType a : AppType.values()) {
            if (a.displayName().equalsIgnoreCase(appName) || a.name().equalsIgnoreCase(appName)) {
                blockApp(a);
                return;
            }
        }
        System.err.println("[RuleManager] Unknown app: " + appName);
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.displayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ========== Domain Blocking ==========

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) {
                return true;
            }
            String lower = domain.toLowerCase();
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lower, pattern.toLowerCase())) {
                    return true;
                }
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            if (domain.endsWith(suffix)) return true;
            if (domain.equals(pattern.substring(2))) return true;
        }
        return false;
    }

    // ========== Port Blocking ==========

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ========== Combined Check ==========

    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockType.IP, ipToString(srcIp)));
        }
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockType.PORT, String.valueOf(dstPort)));
        }
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockType.APP, app.displayName()));
        }
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockType.DOMAIN, domain));
        }
        return Optional.empty();
    }

    // ========== Persistence ==========

    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIps()) {
                writer.println(ip);
            }

            writer.println("\n[BLOCKED_APPS]");
            appLock.readLock().lock();
            try {
                for (AppType a : blockedApps) {
                    writer.println(a.name());
                }
            } finally {
                appLock.readLock().unlock();
            }

            writer.println("\n[BLOCKED_DOMAINS]");
            domainLock.readLock().lock();
            try {
                for (String d : blockedDomains) writer.println(d);
                for (String p : domainPatterns) writer.println(p);
            } finally {
                domainLock.readLock().unlock();
            }

            writer.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int p : blockedPorts) writer.println(p);
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        File file = new File(filename);
        if (!file.exists()) {
            System.err.println("[RuleManager] Rules file not found: " + filename);
            return false;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            String section = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]" -> blockIp(line);
                    case "[BLOCKED_APPS]" -> blockApp(line);
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (Exception e) {
            System.err.println("[RuleManager] Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        try { blockedIps.clear(); } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();
        try { blockedApps.clear(); } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock();
        try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();
        try { blockedPorts.clear(); } finally { portLock.writeLock().unlock(); }
        System.out.println("[RuleManager] All rules cleared");
    }

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    public RuleStats getStats() {
        ipLock.readLock().lock();
        int ips;
        try { ips = blockedIps.size(); } finally { ipLock.readLock().unlock(); }

        appLock.readLock().lock();
        int apps;
        try { apps = blockedApps.size(); } finally { appLock.readLock().unlock(); }

        domainLock.readLock().lock();
        int doms;
        try { doms = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }

        portLock.readLock().lock();
        int ports;
        try { ports = blockedPorts.size(); } finally { portLock.readLock().unlock(); }

        return new RuleStats(ips, apps, doms, ports);
    }

    public static long parseIp(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip.toCharArray()) {
            if (c == '.') {
                result |= ((long) octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= ((long) octet << shift);
        return result & 0xFFFFFFFFL;
    }

    public static String ipToString(long ip) {
        return (ip & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }
}

