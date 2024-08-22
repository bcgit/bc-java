package org.bouncycastle.pqc.crypto.slhdsa;

class IndexedDigest
{
    final long idx_tree;
    final int idx_leaf;
    final byte[] digest;

    IndexedDigest(long idx_tree, int idx_leaf, byte[] digest)
    {
        this.idx_tree = idx_tree;
        this.idx_leaf = idx_leaf;
        this.digest = digest;
    }
}
