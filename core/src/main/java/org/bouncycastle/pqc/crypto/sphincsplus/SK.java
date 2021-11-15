package org.bouncycastle.pqc.crypto.sphincsplus;

class SK
{
    final byte[] seed;
    final byte[] prf;

    SK(byte[] seed, byte[] prf)
    {
        this.seed = seed;
        this.prf = prf;
    }
}
