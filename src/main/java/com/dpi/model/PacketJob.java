package com.dpi.model;

public class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = 0;
    public int payloadLength = 0;
    public int tcpFlags = 0;
    public long tsSec;
    public long tsUsec;
}

