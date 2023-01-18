package org.bouncycastle.mls;

import java.util.Objects;

public class NodeIndex {
    private final long value;

    public long value() {
        return value;
    }

    public NodeIndex(long valueIn) {
        value = valueIn;
    }

    public NodeIndex(LeafIndex leaf) {
        value = 2 * leaf.value();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        NodeIndex nodeIndex = (NodeIndex) o;
        return value == nodeIndex.value;
    }

    public static NodeIndex root(TreeSize size) {
        return new NodeIndex((1L << (size.depth() - 1)) - 1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    private long level() {
        return Long.numberOfTrailingZeros(~value);
    }

    public boolean isLeaf() {
        return value % 2 == 0;
    }

    public boolean isBelow(NodeIndex other) {
        long lx = level();
        long ly = other.level();
        return (lx <= ly) && (value >> (ly+1)) == (other.value >> (ly+1));
    }

    public NodeIndex parent() {
        long k = level();
        return new NodeIndex((value | (1L << k)) & ~(1L << (k+1)));
    }

    public NodeIndex left() {
        if (isLeaf()) {
            return this;
        }

        long k = level();
        return new NodeIndex(value ^ (0x01L << (k - 1)));
    }

    public NodeIndex right() {
        if (isLeaf()) {
            return this;
        }

        long k = level();
        return new NodeIndex(value ^ (0x03L << (k - 1)));
    }

    public NodeIndex sibling() {
        NodeIndex p = parent();
        NodeIndex l = p.left();
        if (!this.equals(l)) {
            return l;
        }

        return p.right();
    }
}
