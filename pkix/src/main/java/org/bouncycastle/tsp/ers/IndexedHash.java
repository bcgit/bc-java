package org.bouncycastle.tsp.ers;

class IndexedHash
{
    final int    order;
    final byte[] digest;

    IndexedHash(int order, byte[] digest)
    {
        this.order = order;
        this.digest = digest;
    }
}
