package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.TreeSize;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Vector;

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
        return new NodeIndex((1L << size.depth()) - 1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    public long level() {
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

//    public NodeIndex sibling() {
//        NodeIndex p = parent();
//        NodeIndex l = p.left();
//        if (!this.equals(l)) {
//            return l;
//        }
//
//        return p.right();
//    }

    public NodeIndex sibling()
    {
        return sibling(parent());
    }
    public NodeIndex sibling(NodeIndex ancestor)
    {
        NodeIndex l = ancestor.left();
        NodeIndex r = ancestor.right();

        if (isBelow(l))
        {
            return r;
        }
        return l;
    }

    public List<NodeIndex> copath(TreeSize size)
    {
        List<NodeIndex> d = directPath(size);

        if (d.isEmpty())
        {
            return new ArrayList<>();
        }

        d.add(0, this);
        d.remove(d.size() - 1);

        List<NodeIndex> cp = new ArrayList<>();
        for (NodeIndex n: d)
        {
            cp.add(n.sibling());
        }

        return cp;
    }

    private  List<NodeIndex> directPath(TreeSize size)
    {
        if (value >= size.width())
        {
            System.out.println("!!!Request for dirpath outside of tree!!!");
        }

        List<NodeIndex> d = new Vector<>();
        NodeIndex r = NodeIndex.root(size);
        if (this.equals(r))
        {
            return d;
        }

        NodeIndex p = parent();
        while (!p.equals(r))
        {
            d.add(p);
            p = p.parent();
        }

        if (!this.equals(r))
        {
            d.add(p);
        }

        return d;
    }
}
