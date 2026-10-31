package com.dpi.pipeline;

import com.dpi.model.FiveTuple;
import com.dpi.model.PacketJob;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer implements Runnable {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private volatile boolean running = false;
    private Thread thread;

    private final AtomicLong received = new AtomicLong(0);
    private final AtomicLong dispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpQueues = fpQueues;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.perFpCounts = new long[numFps];
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this, "LB-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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
        System.out.println("[LB" + lbId + "] Stopped");
    }

    @Override
    public void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.popWithTimeout(100);
                if (job == null) continue;

                received.incrementAndGet();
                int fpIndex = selectFP(job.tuple);

                fpQueues.get(fpIndex).push(job);
                dispatched.incrementAndGet();
                perFpCounts[fpIndex]++;

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private int selectFP(FiveTuple tuple) {
        return (tuple.hashCode() & Integer.MAX_VALUE) % numFps;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public long getReceived() {
        return received.get();
    }

    public long getDispatched() {
        return dispatched.get();
    }

    public int getId() {
        return lbId;
    }
}

