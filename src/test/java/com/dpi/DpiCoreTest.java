package com.dpi;

import com.dpi.inspector.DnsExtractor;
import com.dpi.inspector.HttpHostExtractor;
import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import com.dpi.rules.RuleManager;
import com.dpi.util.AppClassifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class DpiCoreTest {

    @Test
    @DisplayName("FiveTuple hash consistency and equality verification")
    void testFiveTupleHashing() {
        FiveTuple t1 = new FiveTuple(3232235777L, 3232235778L, 443, 50123, 6);
        FiveTuple t2 = new FiveTuple(3232235777L, 3232235778L, 443, 50123, 6);
        FiveTuple t3 = new FiveTuple(3232235778L, 3232235777L, 50123, 443, 6);

        assertEquals(t1, t2);
        assertEquals(t1.hashCode(), t2.hashCode());
        assertNotEquals(t1, t3);

        FiveTuple reversed = t1.reverse();
        assertEquals(t3.srcIp, reversed.srcIp);
        assertEquals(t3.dstIp, reversed.dstIp);
        assertEquals(t3.srcPort, reversed.srcPort);
        assertEquals(t3.dstPort, reversed.dstPort);
    }

    @Test
    @DisplayName("RuleManager IP, Application, Port and Wildcard Domain Matching")
    void testRuleManagerPolicyChecks() {
        RuleManager ruleManager = new RuleManager();

        ruleManager.blockIp("192.168.1.50");
        long blockedIp = RuleManager.parseIp("192.168.1.50");
        long allowedIp = RuleManager.parseIp("192.168.1.51");

        assertTrue(ruleManager.isIpBlocked(blockedIp));
        assertFalse(ruleManager.isIpBlocked(allowedIp));

        ruleManager.blockApp(AppType.YOUTUBE);
        assertTrue(ruleManager.isAppBlocked(AppType.YOUTUBE));
        assertFalse(ruleManager.isAppBlocked(AppType.SPOTIFY));

        ruleManager.blockPort(23);
        assertTrue(ruleManager.isPortBlocked(23));
        assertFalse(ruleManager.isPortBlocked(80));

        ruleManager.blockDomain("*.tiktok.com");
        assertTrue(ruleManager.isDomainBlocked("v16.tiktok.com"));
        assertTrue(ruleManager.isDomainBlocked("tiktok.com"));
        assertFalse(ruleManager.isDomainBlocked("example.com"));

        var blockReason = ruleManager.shouldBlock(blockedIp, 443, AppType.UNKNOWN, "example.com");
        assertTrue(blockReason.isPresent());
        assertEquals(RuleManager.BlockType.IP, blockReason.get().type());
    }

    @Test
    @DisplayName("RuleManager Rule File Persistence (Save & Load)")
    void testRuleManagerPersistence() throws IOException {
        File tempRules = File.createTempFile("dpi_rules_test", ".txt");
        tempRules.deleteOnExit();

        RuleManager rm1 = new RuleManager();
        rm1.blockIp("10.0.0.1");
        rm1.blockApp("YouTube");
        rm1.blockDomain("*.netflix.com");
        rm1.blockPort(445);
        assertTrue(rm1.saveRules(tempRules.getAbsolutePath()));

        RuleManager rm2 = new RuleManager();
        assertTrue(rm2.loadRules(tempRules.getAbsolutePath()));
        assertTrue(rm2.isIpBlocked(RuleManager.parseIp("10.0.0.1")));
        assertTrue(rm2.isAppBlocked(AppType.YOUTUBE));
        assertTrue(rm2.isDomainBlocked("cdn.netflix.com"));
        assertTrue(rm2.isPortBlocked(445));
    }

    @Test
    @DisplayName("HTTP Host Extraction from raw bytes")
    void testHttpHostExtraction() {
        String rawHttp = "GET /index.html HTTP/1.1\r\nHost: example.org:8080\r\nUser-Agent: curl\r\n\r\n";
        byte[] payload = rawHttp.getBytes(StandardCharsets.US_ASCII);

        Optional<String> host = HttpHostExtractor.extract(payload, 0, payload.length);
        assertTrue(host.isPresent());
        assertEquals("example.org", host.get());
    }

    @Test
    @DisplayName("DNS Query RFC 1035 wire label decoding")
    void testDnsQueryExtraction() {
        byte[] dnsHeaderAndQuery = new byte[] {
            // Header (12 bytes)
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags (Standard Query, QR=0)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question section: \x06google\x03com\x00
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,                   // Zero terminator
            0x00, 0x01,             // QTYPE A
            0x00, 0x01              // QCLASS IN
        };

        Optional<String> query = DnsExtractor.extractQuery(dnsHeaderAndQuery, 0, dnsHeaderAndQuery.length);
        assertTrue(query.isPresent());
        assertEquals("google.com", query.get());
    }

    @Test
    @DisplayName("Application classifier fingerprint heuristics")
    void testAppClassifier() {
        assertEquals(AppType.YOUTUBE, AppClassifier.sniToAppType("m.youtube.com"));
        assertEquals(AppType.TIKTOK, AppClassifier.sniToAppType("api16-normal-c-useast1a.tiktokv.com"));
        assertEquals(AppType.GITHUB, AppClassifier.sniToAppType("raw.githubusercontent.com"));
        assertEquals(AppType.UNKNOWN, AppClassifier.sniToAppType("randomunregistereddomain12345.org"));
    }
}
