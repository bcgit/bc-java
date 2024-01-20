package org.bouncycastle.mls;

public class TreeSize {
    private final long leafCount;
    private final long depth;

    private TreeSize(long leafCount, long depth) {
        this.leafCount = leafCount;
        this.depth = depth;
    }

    public static TreeSize forLeaves(long leafCount) {
        assert leafCount >= 0;
        long depth = Long.SIZE - Long.numberOfLeadingZeros(leafCount - 1);
        return new TreeSize(leafCount, depth);
    }

    public long depth() {
        return depth;
    }

    public long leafCount() {
        return leafCount;
    }

    public long width() {
        return (1L << (depth + 1)) - 1;
    }
}
