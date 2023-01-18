package org.bouncycastle.mls;
public class TreeSize {
    private final long depth;

    private TreeSize(long depthIn) {
        depth = depthIn;
    }

    public static TreeSize forLeaves(long leafCount) {
        assert leafCount >= 0;

        long depth = Long.SIZE - Long.numberOfLeadingZeros(leafCount);
        if (leafCount > (1L << (depth - 1))) {
            depth += 1;
        }

        return new TreeSize(depth);
    }

    public long depth() {
        return depth;
    }

    public long leafCount() {
        return 1L << (depth - 1);
    }

    public long width() {
        return 2 * leafCount() - 1;
    }
}
