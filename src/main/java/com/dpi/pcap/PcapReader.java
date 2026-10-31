package com.dpi.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements Closeable {
    private static final int MAGIC_BIG_ENDIAN    = 0xa1b2c3d4;
    private static final int MAGIC_LITTLE_ENDIAN = 0xd4c3b2a1;

    private InputStream in;
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;
    private PcapGlobalHeader globalHeader;

    public boolean open(String filename) throws IOException {
        File file = new File(filename);
        if (!file.exists()) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }

        in = new BufferedInputStream(new FileInputStream(file));
        byte[] magicBytes = in.readNBytes(4);
        if (magicBytes.length < 4) {
            System.err.println("Error: Could not read PCAP global header");
            close();
            return false;
        }

        ByteBuffer magicBuf = ByteBuffer.wrap(magicBytes);
        int rawMagic = magicBuf.getInt(); // default big-endian read
        if (rawMagic == MAGIC_BIG_ENDIAN) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (rawMagic == MAGIC_LITTLE_ENDIAN) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            System.err.printf("Error: Invalid PCAP magic number: 0x%08x%n", rawMagic);
            close();
            return false;
        }

        byte[] headerRest = in.readNBytes(20);
        if (headerRest.length < 20) {
            System.err.println("Error: Could not read full PCAP global header");
            close();
            return false;
        }

        ByteBuffer bb = ByteBuffer.wrap(headerRest).order(byteOrder);
        globalHeader = new PcapGlobalHeader();
        globalHeader.magicNumber = Integer.toUnsignedLong(MAGIC_BIG_ENDIAN);
        globalHeader.versionMajor = Short.toUnsignedInt(bb.getShort());
        globalHeader.versionMinor = Short.toUnsignedInt(bb.getShort());
        globalHeader.thiszone = bb.getInt();
        globalHeader.sigfigs = Integer.toUnsignedLong(bb.getInt());
        globalHeader.snaplen = Integer.toUnsignedLong(bb.getInt());
        globalHeader.network = Integer.toUnsignedLong(bb.getInt());

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
        System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
        System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));

        return true;
    }

    public RawPacket readNextPacket() throws IOException {
        if (in == null) return null;

        byte[] headerBytes = in.readNBytes(16);
        if (headerBytes.length < 16) {
            return null; // EOF
        }

        ByteBuffer bb = ByteBuffer.wrap(headerBytes).order(byteOrder);
        RawPacket pkt = new RawPacket();
        pkt.header.tsSec = Integer.toUnsignedLong(bb.getInt());
        pkt.header.tsUsec = Integer.toUnsignedLong(bb.getInt());
        pkt.header.inclLen = Integer.toUnsignedLong(bb.getInt());
        pkt.header.origLen = Integer.toUnsignedLong(bb.getInt());

        if (pkt.header.inclLen > globalHeader.snaplen || pkt.header.inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + pkt.header.inclLen);
            return null;
        }

        pkt.data = in.readNBytes((int) pkt.header.inclLen);
        if (pkt.data.length < pkt.header.inclLen) {
            System.err.println("Error: Could not read packet data");
            return null;
        }

        return pkt;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public static void writeGlobalHeader(OutputStream out, PcapGlobalHeader h) throws IOException {
        // Write standard little-endian PCAP header for broad compatibility
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) 0xa1b2c3d4);
        bb.putShort((short) (h != null ? h.versionMajor : 2));
        bb.putShort((short) (h != null ? h.versionMinor : 4));
        bb.putInt(h != null ? h.thiszone : 0);
        bb.putInt((int) (h != null ? h.sigfigs : 0));
        bb.putInt((int) (h != null ? h.snaplen : 65535));
        bb.putInt((int) (h != null ? h.network : 1));
        out.write(bb.array());
    }

    public static void writePacket(OutputStream out, long tsSec, long tsUsec, byte[] data) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) tsSec);
        bb.putInt((int) tsUsec);
        bb.putInt(data.length);
        bb.putInt(data.length);
        out.write(bb.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }
}

