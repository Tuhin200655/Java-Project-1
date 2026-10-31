package com.dpi.pipeline;

import com.dpi.model.FiveTuple;
import com.dpi.model.PacketJob;

import java.util.ArrayList;
import java.util.List;

public class LbManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final int fpsPerLb;

    public LbManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int fpStart = lbId * fpsPerLb;
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = fpQueues.subList(fpStart, fpStart + fpsPerLb);
            lbs.add(new LoadBalancer(lbId, new ArrayList<>(lbFpQueues), fpStart));
        }
        System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
    }

    public void startAll() {
        lbs.forEach(LoadBalancer::start);
    }

    public void stopAll() {
        lbs.forEach(LoadBalancer::stop);
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int idx = (tuple.hashCode() & Integer.MAX_VALUE) % lbs.size();
        return lbs.get(idx);
    }

    public LoadBalancer getLB(int id) {
        return lbs.get(id);
    }

    public int getNumLBs() {
        return lbs.size();
    }

    public record AggregatedStats(long totalReceived, long totalDispatched) {}

    public AggregatedStats getAggregatedStats() {
        long r = 0, d = 0;
        for (LoadBalancer lb : lbs) {
            r += lb.getReceived();
            d += lb.getDispatched();
        }
        return new AggregatedStats(r, d);
    }
}

