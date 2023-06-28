package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;
import java.util.Objects;
import java.util.List;
import java.util.Vector;
import java.util.stream.Collectors;

public class LeafIndex
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    protected int value;


    //TODO: make this an int not a long?
    public int value() {
        return value;
    }

    public LeafIndex(int valueIn) {
        value = valueIn;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        LeafIndex leafIndex = (LeafIndex) o;
        return value == leafIndex.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    public NodeIndex commonAncestor(LeafIndex other) {
        if (this.equals(other)) {
            return new NodeIndex(this);
        }

        long k = 0;
        long xv = (new NodeIndex(this)).value();
        long yv = (new NodeIndex(other)).value();
        while (xv != yv) {
            xv >>= 1;
            yv >>= 1;
            k += 1;
        }

        long prefix = xv << k;
        long stop = (1L << (k - 1));
        return new NodeIndex( prefix + stop - 1);
    }

    public List<NodeIndex> directPath(TreeSize size) {
        List<NodeIndex> d = new Vector<>();

        NodeIndex n = new NodeIndex(this);
        NodeIndex r = NodeIndex.root(size);
        if (n.equals(r)) {
            return d;
        }

        NodeIndex p = n.parent();
        while (!p.equals(r)) {
            d.add(p);
            p = p.parent();
        }

        // Include the root unless this is a one-member tree
        if (!n.equals(r)) {
            d.add(p);
        }

        return d;
    }

    public List<NodeIndex> copath(TreeSize size) {
        List<NodeIndex> d = directPath(size);
        if (d.isEmpty()) {
            return d;
        }

        // Prepend leaf; omit root
        d.add(0, new NodeIndex(this));
        d.remove(d.size() - 1);

        return d.stream()
                .map(NodeIndex::sibling)
                .collect(Collectors.toList());
    }
    public LeafIndex(MLSInputStream stream) throws IOException
    {
        value = (int) stream.read(int.class);
    }
    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(value);
    }
}
