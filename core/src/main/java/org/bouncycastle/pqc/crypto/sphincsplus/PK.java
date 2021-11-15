package org.bouncycastle.pqc.crypto.sphincsplus;

class PK
{
    final byte[] seed;
    final byte[] root;

    PK(byte[] seed, byte[] root)
    {
        this.seed = seed;
        this.root = root;
    }
}
