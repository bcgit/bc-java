package org.bouncycastle.pqc.crypto.sike;

class PointProj
{
    PointProj(int nwords_field)
    {
        X = new long[2][nwords_field];
        Z = new long[2][nwords_field];
    }

    public long[][] X;
    public long[][] Z;
}
