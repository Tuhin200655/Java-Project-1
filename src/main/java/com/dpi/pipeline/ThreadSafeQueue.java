package com.dpi.pipeline;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ThreadSafeQueue<T> {
    private final ArrayBlockingQueue<T> queue;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    private final int maxSize;

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
        this.queue = new ArrayBlockingQueue<>(maxSize);
    }

    public void push(T item) throws InterruptedException {
        while (!shutdown.get()) {
            if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) {
                return;
            }
        }
    }

    public boolean tryPush(T item) {
        if (shutdown.get()) return false;
        return queue.offer(item);
    }

    public T pop() throws InterruptedException {
        while (!shutdown.get() || !queue.isEmpty()) {
            T item = queue.poll(100, TimeUnit.MILLISECONDS);
            if (item != null) return item;
        }
        return null;
    }

    public T popWithTimeout(long timeoutMs) throws InterruptedException {
        return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    public void shutdown() {
        shutdown.set(true);
    }

    public boolean isShutdown() {
        return shutdown.get();
    }
}

