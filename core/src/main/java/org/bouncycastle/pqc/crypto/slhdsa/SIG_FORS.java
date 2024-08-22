package org.bouncycastle.pqc.crypto.slhdsa;

class SIG_FORS
{
    final byte[][] authPath;
    final byte[] sk;

    SIG_FORS(byte[] sk, byte[][] authPath)
    {
        this.authPath = authPath;
        this.sk = sk;
    }

    byte[] getSK()
    {
        return sk;
    }

    public byte[][] getAuthPath()
    {
        return authPath;
    }
}
